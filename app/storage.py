"""SQLite-backed storage for scan results."""
import json
import os
import sqlite3
import threading
import time

_DB_PATH = os.environ.get('PHISHGUARD_DB_PATH', 'data/phishguard.db')
_lock = threading.Lock()


def _conn():
    os.makedirs(os.path.dirname(_DB_PATH), exist_ok=True)
    c = sqlite3.connect(_DB_PATH, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _lock:
        c = _conn()
        c.execute('''CREATE TABLE IF NOT EXISTS trusted_domains (
            domain TEXT PRIMARY KEY,
            added_at REAL NOT NULL,
            added_by TEXT DEFAULT 'user',
            note TEXT DEFAULT ''
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS feedback (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            original_verdict TEXT,
            corrected_verdict TEXT NOT NULL,
            notes TEXT DEFAULT '',
            submitted_at REAL NOT NULL,
            submitted_by TEXT DEFAULT 'soc'
        )''')
        # Pending SOC review queue — suspicious emails held for analyst approval
        c.execute('''CREATE TABLE IF NOT EXISTS pending_review (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            ts REAL NOT NULL,
            verdict TEXT NOT NULL,
            confidence REAL NOT NULL,
            sender TEXT,
            subject TEXT,
            original_rcpt TEXT NOT NULL,
            raw_email BLOB NOT NULL,
            status TEXT DEFAULT 'pending',
            reviewed_by TEXT,
            reviewed_at REAL
        )''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_pr_status ON pending_review(status)')
        c.execute('''CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            ts REAL NOT NULL,
            verdict TEXT NOT NULL,
            confidence REAL NOT NULL,
            blocked_at TEXT,
            sender TEXT,
            subject TEXT,
            body_preview TEXT,
            data_json TEXT NOT NULL,
            released INTEGER DEFAULT 0,
            deleted INTEGER DEFAULT 0
        )''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_ts ON scans(ts DESC)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_verdict ON scans(verdict)')
        c.commit()
        c.close()


def save_scan(scan_id, result, parsed):
    with _lock:
        c = _conn()
        body = parsed.get('body_text', '') or ''
        prev = body[:300] if body else ''
        c.execute('''INSERT OR REPLACE INTO scans
            (id, ts, verdict, confidence, blocked_at, sender, subject, body_preview, data_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (scan_id,
             time.time(),
             result.get('verdict', 'unknown'),
             float(result.get('confidence', 0)),
             result.get('blocked_at', None),
             parsed.get('from_header', ''),
             parsed.get('subject', ''),
             prev,
             json.dumps(_safe(result))))
        c.commit()
        c.close()


def _safe(obj):
    try:
        json.dumps(obj)
        return obj
    except Exception:
        return {'note': 'truncated', 'verdict': obj.get('verdict')}


def list_scans(limit=50, offset=0, verdict_filter=None, only_quarantined=False, since_ts: float | None = None):
    with _lock:
        c = _conn()
        sql = 'SELECT id, ts, verdict, confidence, blocked_at, sender, subject, body_preview, released, deleted FROM scans WHERE deleted = 0'
        params = []
        if only_quarantined:
            sql += " AND verdict IN ('phishing', 'suspicious') AND released = 0"
        if verdict_filter:
            sql += ' AND verdict = ?'
            params.append(verdict_filter)
        if since_ts is not None:
            sql += ' AND ts >= ?'
            params.append(since_ts)
        sql += ' ORDER BY ts DESC LIMIT ? OFFSET ?'
        params.append(limit)
        params.append(offset)
        rows = c.execute(sql, params).fetchall()
        c.close()
        return [dict(r) for r in rows]


def get_scan(scan_id):
    with _lock:
        c = _conn()
        row = c.execute('SELECT * FROM scans WHERE id = ?', (scan_id,)).fetchone()
        c.close()
        if not row:
            return None
        d = dict(row)
        try:
            d['data'] = json.loads(d.pop('data_json'))
        except Exception:
            d['data'] = {}
        return d


def release_scan(scan_id):
    with _lock:
        c = _conn()
        c.execute('UPDATE scans SET released = 1 WHERE id = ?', (scan_id,))
        c.commit()
        c.close()


def delete_scan(scan_id):
    with _lock:
        c = _conn()
        c.execute('UPDATE scans SET deleted = 1 WHERE id = ?', (scan_id,))
        c.commit()
        c.close()


def get_stats(since_ts: float | None = None):
    with _lock:
        c = _conn()
        sql = "SELECT verdict, COUNT(*) AS cnt FROM scans WHERE deleted = 0"
        params = []
        if since_ts is not None:
            sql += " AND ts >= ?"
            params.append(since_ts)
        sql += " GROUP BY verdict"
        rows = c.execute(sql, params).fetchall()
        c.close()
        out = {'phishing': 0, 'suspicious': 0, 'clean': 0, 'total': 0}
        for r in rows:
            v = r['verdict']
            n = r['cnt']
            out[v] = out.get(v, 0) + n
            out['total'] += n
        return out


def save_pending_review(pending_id: str, scan_id: str, verdict: str, confidence: float,
                        sender: str, subject: str, original_rcpt: str, raw_email: bytes) -> bool:
    with _lock:
        c = _conn()
        try:
            c.execute('''INSERT OR REPLACE INTO pending_review
                (id, scan_id, ts, verdict, confidence, sender, subject, original_rcpt, raw_email, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')''',
                (pending_id, scan_id, time.time(), verdict, float(confidence),
                 sender, subject, original_rcpt, raw_email))
            c.commit()
            return True
        except Exception as exc:
            import structlog; structlog.get_logger().warning("pending_save_err", error=str(exc))
            return False
        finally:
            c.close()


def list_pending_reviews(status: str = "pending") -> list[dict]:
    with _lock:
        c = _conn()
        rows = c.execute(
            '''SELECT id, scan_id, ts, verdict, confidence, sender, subject,
               original_rcpt, status, reviewed_by, reviewed_at
               FROM pending_review WHERE status = ? ORDER BY ts DESC''',
            (status,)
        ).fetchall()
        c.close()
        keys = ["id","scan_id","ts","verdict","confidence","sender",
                "subject","original_rcpt","status","reviewed_by","reviewed_at"]
        return [dict(zip(keys, r)) for r in rows]


def get_pending_raw(pending_id: str) -> bytes | None:
    with _lock:
        c = _conn()
        row = c.execute("SELECT raw_email FROM pending_review WHERE id=?", (pending_id,)).fetchone()
        c.close()
        return row[0] if row else None


def update_pending_status(pending_id: str, status: str, reviewed_by: str = "") -> bool:
    with _lock:
        c = _conn()
        c.execute("UPDATE pending_review SET status=?, reviewed_by=?, reviewed_at=? WHERE id=?",
                  (status, reviewed_by, time.time(), pending_id))
        c.commit()
        c.close()
        return True


def list_trusted_domains() -> list[dict]:
    with _lock:
        c = _conn()
        rows = c.execute('SELECT domain, added_at, note FROM trusted_domains ORDER BY added_at DESC').fetchall()
        c.close()
        return [{'domain': r[0], 'added_at': r[1], 'note': r[2]} for r in rows]


def add_trusted_domain(domain: str, note: str = '', added_by: str = 'user') -> bool:
    with _lock:
        c = _conn()
        try:
            c.execute('INSERT OR REPLACE INTO trusted_domains (domain, added_at, added_by, note) VALUES (?, ?, ?, ?)',
                      (domain.lower().strip(), time.time(), added_by, note))
            c.commit()
            return True
        except Exception:
            return False
        finally:
            c.close()


def remove_trusted_domain(domain: str) -> bool:
    with _lock:
        c = _conn()
        c.execute('DELETE FROM trusted_domains WHERE domain = ?', (domain.lower().strip(),))
        c.commit()
        c.close()
        return True


def save_feedback(scan_id: str, original_verdict: str, corrected_verdict: str,
                  notes: str = '', submitted_by: str = 'soc') -> bool:
    import uuid as _uuid
    with _lock:
        c = _conn()
        try:
            c.execute('''INSERT INTO feedback
                (id, scan_id, original_verdict, corrected_verdict, notes, submitted_at, submitted_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (_uuid.uuid4().hex, scan_id, original_verdict, corrected_verdict, notes,
                 time.time(), submitted_by))
            c.commit()
            return True
        except Exception:
            return False
        finally:
            c.close()


init_db()

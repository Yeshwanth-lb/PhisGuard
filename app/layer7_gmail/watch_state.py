"""Layer 7 - Per-mailbox watch state: tracks each domain mailbox's Gmail
watch() expiry so the renewal scheduler knows what's about to go dark.

Gmail watches expire after 7 days with no warning delivered anywhere —
without tracking this ourselves, a mailbox silently stops receiving push
notifications and nobody notices until someone asks "why didn't this get
flagged". Mirrors the sqlite checkpoint pattern already used in
historical_scanner.py.
"""
import sqlite3
import time

_STATE_DB = "data/gmail_watch_state.db"


def _conn() -> sqlite3.Connection:
    import os
    os.makedirs("data", exist_ok=True)
    c = sqlite3.connect(_STATE_DB, check_same_thread=False)
    c.execute("""CREATE TABLE IF NOT EXISTS mailbox_watches (
        user_email   TEXT PRIMARY KEY,
        history_id   TEXT,
        expiry_ms    INTEGER,
        updated_at   REAL NOT NULL
    )""")
    c.commit()
    return c


def save_watch(user_email: str, history_id: str | None, expiry_ms: str | int | None) -> None:
    conn = _conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO mailbox_watches (user_email, history_id, expiry_ms, updated_at) "
            "VALUES (?,?,?,?)",
            (user_email, history_id, int(expiry_ms) if expiry_ms else None, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def get_watch(user_email: str) -> dict | None:
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT user_email, history_id, expiry_ms, updated_at FROM mailbox_watches WHERE user_email=?",
            (user_email,),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {"user_email": row[0], "history_id": row[1], "expiry_ms": row[2], "updated_at": row[3]}


def list_all() -> list[dict]:
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT user_email, history_id, expiry_ms, updated_at FROM mailbox_watches"
        ).fetchall()
    finally:
        conn.close()
    return [{"user_email": r[0], "history_id": r[1], "expiry_ms": r[2], "updated_at": r[3]} for r in rows]


def list_expiring_within(hours: int = 24) -> list[str]:
    """Return user_emails whose watch expires within `hours`, or has no
    recorded expiry at all (never registered / state lost — treat as
    expiring now, safer than silently skipping it)."""
    cutoff_ms = int((time.time() + hours * 3600) * 1000)
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT user_email FROM mailbox_watches WHERE expiry_ms IS NULL OR expiry_ms <= ?",
            (cutoff_ms,),
        ).fetchall()
    finally:
        conn.close()
    return [r[0] for r in rows]


def health_summary(expiring_hours: int = 24) -> dict:
    """Fleet watch-health rollup for observability: how many mailboxes are
    protected, expiring soon, or in an unknown/stale state. This is the data a
    dashboard tile renders; safe to call with zero watches (returns zeros)."""
    now_ms = time.time() * 1000
    cutoff_ms = now_ms + expiring_hours * 3600 * 1000
    all_rows = list_all()
    protected = expiring = stale = 0
    soonest_expiry_ms = None
    for r in all_rows:
        exp = r.get("expiry_ms")
        if exp is None:
            stale += 1
        elif exp <= now_ms:
            stale += 1          # already expired = going dark now
        elif exp <= cutoff_ms:
            expiring += 1
            soonest_expiry_ms = exp if soonest_expiry_ms is None else min(soonest_expiry_ms, exp)
        else:
            protected += 1
            soonest_expiry_ms = exp if soonest_expiry_ms is None else min(soonest_expiry_ms, exp)
    return {
        "total_mailboxes": len(all_rows),
        "protected": protected,
        "expiring_soon": expiring,
        "stale_or_expired": stale,
        "expiring_window_hours": expiring_hours,
        "soonest_expiry_ms": soonest_expiry_ms,
        "healthy": stale == 0,
    }

"""Layer 4 - block-list storage and lookup.

Auto-populated when phishing is detected. Layer 1 consults this
table as a hard block before any external OSINT calls.
"""
import os
import sqlite3
import time

DB_PATH = os.path.join("data", "denylist.db")


def _conn() -> sqlite3.Connection:
    os.makedirs("data", exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.execute("""CREATE TABLE IF NOT EXISTS denylist (
        kind TEXT NOT NULL,
        value TEXT NOT NULL,
        reason TEXT,
        added_at REAL NOT NULL,
        added_by TEXT,
        active INTEGER DEFAULT 1,
        hit_count INTEGER DEFAULT 0,
        last_hit REAL,
        PRIMARY KEY (kind, value)
    )""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_kind_active ON denylist(kind, active)")
    c.commit()
    return c


def add_entry(kind: str, value: str, reason: str = "", added_by: str = "auto") -> bool:
    if not value:
        return False
    value = value.strip().lower()
    c = _conn()
    try:
        c.execute(
            "INSERT OR REPLACE INTO denylist (kind, value, reason, added_at, added_by, active) VALUES (?, ?, ?, ?, ?, 1)",
            (kind, value, reason, time.time(), added_by),
        )
        c.commit()
        return True
    finally:
        c.close()


def remove_entry(kind: str, value: str) -> bool:
    if not value:
        return False
    c = _conn()
    try:
        c.execute("UPDATE denylist SET active = 0 WHERE kind = ? AND value = ?", (kind, value.strip().lower()))
        c.commit()
        return True
    finally:
        c.close()


def is_denied(kind: str, value: str) -> tuple[str, float] | None:
    if not value:
        return None
    c = _conn()
    try:
        cur = c.execute(
            "SELECT reason, added_at FROM denylist WHERE kind = ? AND value = ? AND active = 1",
            (kind, value.strip().lower()),
        )
        row = cur.fetchone()
        if not row:
            return None
        c.execute(
            "UPDATE denylist SET hit_count = hit_count + 1, last_hit = ? WHERE kind = ? AND value = ?",
            (time.time(), kind, value.strip().lower()),
        )
        c.commit()
        return (row[0] or "", row[1])
    finally:
        c.close()


def list_entries(kind: str | None = None, only_active: bool = True, limit: int = 500) -> list[dict]:
    c = _conn()
    try:
        sql = "SELECT kind, value, reason, added_at, added_by, active, hit_count, last_hit FROM denylist"
        params: list = []
        clauses = []
        if only_active:
            clauses.append("active = 1")
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY added_at DESC LIMIT ?"
        params.append(limit)
        rows = c.execute(sql, params).fetchall()
        out = []
        for r in rows:
            out.append({
                "kind": r[0], "value": r[1], "reason": r[2],
                "added_at": r[3], "added_by": r[4], "active": bool(r[5]),
                "hit_count": r[6], "last_hit": r[7],
            })
        return out
    finally:
        c.close()


def stats() -> dict:
    c = _conn()
    try:
        out = {"by_kind": {}, "total": 0, "total_hits": 0}
        rows = c.execute(
            "SELECT kind, COUNT(*), SUM(hit_count) FROM denylist WHERE active = 1 GROUP BY kind"
        ).fetchall()
        for k, n, h in rows:
            out["by_kind"][k] = {"count": n, "hits": h or 0}
            out["total"] += n
            out["total_hits"] += h or 0
        return out
    finally:
        c.close()


# Major shared email providers — never block these domains.
# Blocking gmail.com would deny ALL Gmail users worldwide.
_SHARED_PROVIDER_DOMAINS = {
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.uk", "yahoo.co.in",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me",
    "zoho.com", "aol.com",
}


def auto_populate_from_verdict(verdict_doc: dict) -> list[tuple[str, str]]:
    """Auto-block specific senders/IPs confirmed as malicious.

    Rules:
    - Only fires on high-confidence phishing caught at L1 (OSINT hit) — not
      on AI-only detections, because those carry more false-positive risk.
    - Never adds shared provider domains (gmail.com etc.) — that would block
      millions of legitimate users.
    - Adds specific sender address + IP only; domain only for dedicated
      attacker-owned domains.
    """
    if verdict_doc.get("verdict") != "phishing":
        return []

    # Only auto-block when a real OSINT source confirmed the threat
    blocked_at = verdict_doc.get("blocked_at") or ""
    l1 = verdict_doc.get("l1") or {}
    l1_hits = l1.get("hits", [])
    if blocked_at != "layer1" or not l1_hits:
        # AI/ML-only verdict — too risky to auto-block without OSINT confirmation
        return []

    parsed = verdict_doc.get("parsed") or {}
    confidence = verdict_doc.get("confidence", 0.0)
    reason = f"auto:layer1:conf={confidence:.2f}"
    added = []

    # Always block the specific sender address
    sender = parsed.get("from_header") or parsed.get("sender_email") or ""
    if sender and "@" in sender:
        addr = sender.strip().lower()
        if "<" in addr and ">" in addr:
            addr = addr.split("<", 1)[1].split(">", 1)[0]
        if add_entry("sender", addr, reason):
            added.append(("sender", addr))

        # Block domain ONLY if it's not a shared provider
        domain = addr.split("@")[-1] if "@" in addr else ""
        if domain and domain not in _SHARED_PROVIDER_DOMAINS:
            if add_entry("domain", domain, reason):
                added.append(("domain", domain))

    # Always block the sender IP (infrastructure-level signal)
    ip = parsed.get("sender_ip") or ""
    if ip:
        if add_entry("ip", ip, reason):
            added.append(("ip", ip))

    return added

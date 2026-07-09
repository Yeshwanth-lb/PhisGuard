"""Backend-agnostic DB layer: SQLite (default) or PostgreSQL (deployment).

Additive by design — with no DATABASE_URL set, everything behaves exactly as the
original SQLite code did (native sqlite3 + sqlite3.Row), so the existing demo/dev
setup is untouched. Set DATABASE_URL=postgresql://user:pass@host/db (or
settings.database_url) to run the primary datastore on Postgres for real
concurrent-write durability / backup / HA.

The adapter is deliberately thin: it (a) picks the driver, (b) translates '?'
placeholders to '%s' for psycopg, (c) returns rows that behave like sqlite3.Row
on BOTH backends — positional r[0], named r['col'], AND sequence iteration so
existing patterns like dict(zip(cols, row)) and dict(row) keep working unchanged.
Callers write SQLite-flavored SQL and route DDL/upsert through ddl()/upsert().
"""
from __future__ import annotations

import os


def database_url() -> str:
    """Resolve the configured Postgres URL (empty => SQLite)."""
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        try:
            from app.config import settings
            url = getattr(settings, "database_url", "") or ""
        except Exception:
            url = ""
    return url.strip()


def is_postgres() -> bool:
    return database_url().startswith(("postgres://", "postgresql://"))


# ── DDL / SQL dialect helpers ────────────────────────────────────────────────
def ddl(sql: str) -> str:
    """Translate SQLite-flavored DDL to Postgres where the two differ."""
    if not is_postgres():
        return sql
    return sql.replace(" BLOB", " BYTEA")


def upsert(table: str, columns: list[str], pk) -> str:
    """Dialect-correct 'insert or replace' on the given primary key(s)."""
    cols = ", ".join(columns)
    ph = ", ".join(["?"] * len(columns))
    if not is_postgres():
        return f"INSERT OR REPLACE INTO {table} ({cols}) VALUES ({ph})"
    pks = [pk] if isinstance(pk, str) else list(pk)
    updates = ", ".join(f"{c}=EXCLUDED.{c}" for c in columns if c not in pks)
    return (f"INSERT INTO {table} ({cols}) VALUES ({ph}) "
            f"ON CONFLICT ({', '.join(pks)}) DO UPDATE SET {updates}")


class _PGRow:
    """sqlite3.Row-compatible view over a psycopg tuple: supports positional and
    named indexing, sequence iteration (dict(zip(cols,row))), and mapping
    conversion (dict(row))."""
    __slots__ = ("_vals", "_idx")

    def __init__(self, vals, idx):
        self._vals = vals
        self._idx = idx

    def __getitem__(self, k):
        return self._vals[k if isinstance(k, int) else self._idx[k]]

    def __iter__(self):
        return iter(self._vals)

    def __len__(self):
        return len(self._vals)

    def keys(self):
        return list(self._idx.keys())


class _Cursor:
    def __init__(self, raw, postgres: bool):
        self._c = raw
        self._pg = postgres

    def execute(self, sql: str, params=()):
        if self._pg:
            sql = sql.replace("?", "%s")
        self._c.execute(sql, tuple(params))
        return self

    def _idx(self):
        return {d[0]: i for i, d in enumerate(self._c.description)} if self._c.description else {}

    def fetchone(self):
        row = self._c.fetchone()
        if row is None:
            return None
        return _PGRow(row, self._idx()) if self._pg else row

    def fetchall(self):
        if self._pg:
            idx = self._idx()
            return [_PGRow(r, idx) for r in self._c.fetchall()]
        return self._c.fetchall()


class _Conn:
    def __init__(self, raw, postgres: bool):
        self._raw = raw
        self._pg = postgres

    def execute(self, sql: str, params=()):
        return _Cursor(self._raw.cursor(), self._pg).execute(sql, params)

    def cursor(self):
        return _Cursor(self._raw.cursor(), self._pg)

    def commit(self):
        self._raw.commit()

    def close(self):
        self._raw.close()


def connect(sqlite_path: str) -> _Conn:
    """Open a connection to the configured backend. sqlite_path is used only for
    the SQLite backend (ignored for Postgres)."""
    if is_postgres():
        import psycopg  # psycopg 3
        return _Conn(psycopg.connect(database_url()), postgres=True)
    import sqlite3
    if sqlite_path != ":memory:":
        os.makedirs(os.path.dirname(sqlite_path) or ".", exist_ok=True)
    raw = sqlite3.connect(sqlite_path, check_same_thread=False)
    raw.row_factory = sqlite3.Row
    if sqlite_path != ":memory:":
        try:
            raw.execute("PRAGMA journal_mode=WAL")
            raw.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
    return _Conn(raw, postgres=False)

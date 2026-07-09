"""Backend-agnostic DB adapter: dialect translation + SQLite storage cycle.

The Postgres *runtime* path is validated separately against a real Postgres
instance (see the migration commit / `make`-less manual run); these tests cover
the dialect string generation (no DB needed) and prove the SQLite path — the
default that the whole dev/demo stack runs on — is unchanged.
"""
import importlib
import os
import tempfile

from app import db


def _reload_sqlite():
    os.environ.pop("DATABASE_URL", None)
    importlib.reload(db)


def _force_pg():
    os.environ["DATABASE_URL"] = "postgresql://u:p@localhost/db"
    importlib.reload(db)


def teardown_function(_):
    os.environ.pop("DATABASE_URL", None)
    importlib.reload(db)


class TestDialect:
    def test_sqlite_upsert(self):
        _reload_sqlite()
        sql = db.upsert("scans", ["id", "ts", "verdict"], "id")
        assert sql.startswith("INSERT OR REPLACE INTO scans")
        assert sql.count("?") == 3

    def test_postgres_upsert(self):
        _force_pg()
        sql = db.upsert("scans", ["id", "ts", "verdict"], "id")
        assert "ON CONFLICT (id) DO UPDATE SET" in sql
        assert "ts=EXCLUDED.ts" in sql and "verdict=EXCLUDED.verdict" in sql
        assert "id=EXCLUDED.id" not in sql  # pk not in the update set

    def test_postgres_composite_pk(self):
        _force_pg()
        sql = db.upsert("t", ["a", "b", "c"], ["a", "b"])
        assert "ON CONFLICT (a, b) DO UPDATE SET" in sql
        assert "c=EXCLUDED.c" in sql

    def test_ddl_blob_translation(self):
        _reload_sqlite()
        assert "BLOB" in db.ddl("x BLOB NOT NULL")   # unchanged on sqlite
        _force_pg()
        out = db.ddl("x BLOB NOT NULL")
        assert "BYTEA" in out and "BLOB" not in out

    def test_is_postgres_flag(self):
        _reload_sqlite()
        assert db.is_postgres() is False
        _force_pg()
        assert db.is_postgres() is True


class TestSqliteStorageCycle:
    def test_full_cycle_sqlite(self):
        _reload_sqlite()
        d = tempfile.mkdtemp()
        os.environ["PHISHGUARD_DB_PATH"] = os.path.join(d, "t.db")
        from app import storage
        importlib.reload(storage)
        storage._DB_PATH = os.environ["PHISHGUARD_DB_PATH"]
        storage.init_db()
        storage.save_scan("s1", {"verdict": "phishing", "confidence": 0.9, "blocked_at": "layer2"},
                          {"from_header": "a@b.com", "subject": "hi", "body_text": "body"})
        # upsert dedup: same id must replace, not duplicate
        storage.save_scan("s1", {"verdict": "suspicious", "confidence": 0.5, "blocked_at": None},
                          {"from_header": "a@b.com", "subject": "hi2", "body_text": "b2"})
        rows = storage.list_scans()
        assert len(rows) == 1 and rows[0]["verdict"] == "suspicious"
        assert storage.get_scan("s1")["verdict"] == "suspicious"
        assert storage.save_pending_review("p1", "s1", "suspicious", 0.5, "a@b.com", "h", "u@x.com", b"raw")
        assert storage.get_pending_raw("p1") == b"raw"
        assert storage.add_trusted_domain("example.com")
        assert storage.buffer_add("b1", "v@x.com", "s1", "noise", b"eml")
        os.environ.pop("PHISHGUARD_DB_PATH", None)

"""Tests for the durable bombing buffer + WAL mode (Phase 1A).

Core guarantee under test: buffered mail is written to SQLite (not memory) so it
SURVIVES a restart mid-bomb, and WAL is actually enabled so concurrent writes under
a flood don't throw "database is locked". Each storage call opens its own connection,
so re-reading after the first write exercises the on-disk persistence path.
"""
import app.storage as storage


def _use_tmp_db(tmp_path, monkeypatch):
    db = tmp_path / "buffer_test.db"
    monkeypatch.setattr(storage, "_DB_PATH", str(db))
    storage.init_db()
    return str(db)


def test_wal_mode_enabled(tmp_path, monkeypatch):
    _use_tmp_db(tmp_path, monkeypatch)
    c = storage._conn()
    mode = c.execute("PRAGMA journal_mode").fetchone()[0]
    c.close()
    assert mode.lower() == "wal"


def test_buffer_add_and_list(tmp_path, monkeypatch):
    _use_tmp_db(tmp_path, monkeypatch)
    ok = storage.buffer_add("b1", "Victim@Co.com", "scan1", "noise",
                            b"RAW-MIME-BYTES", "mailchimp.com", "Newsletter")
    assert ok
    held = storage.buffer_list_for_recipient("victim@co.com")   # recipient normalized
    assert len(held) == 1
    assert held[0]["raw_email"] == b"RAW-MIME-BYTES"
    assert held[0]["tier"] == "noise"
    assert held[0]["sender_domain"] == "mailchimp.com"


def test_buffer_survives_restart(tmp_path, monkeypatch):
    """Write, then read back through a fresh connection (== process restart for SQLite)."""
    _use_tmp_db(tmp_path, monkeypatch)
    storage.buffer_add("b1", "v@co.com", "s1", "uncertain", b"AAA")
    storage.buffer_add("b2", "v@co.com", "s2", "noise", b"BBB")
    # Simulate restart: the data is on disk; a new connection (every call opens one)
    # must still see both rows in insertion order.
    held = storage.buffer_list_for_recipient("v@co.com")
    assert [h["id"] for h in held] == ["b1", "b2"]


def test_buffer_mark_released(tmp_path, monkeypatch):
    _use_tmp_db(tmp_path, monkeypatch)
    storage.buffer_add("b1", "v@co.com", "s1", "noise", b"AAA")
    assert len(storage.buffer_list_for_recipient("v@co.com", released=0)) == 1
    storage.buffer_mark_released("b1")
    assert len(storage.buffer_list_for_recipient("v@co.com", released=0)) == 0
    assert len(storage.buffer_list_for_recipient("v@co.com", released=1)) == 1


def test_buffer_purge_expired_only_released(tmp_path, monkeypatch):
    _use_tmp_db(tmp_path, monkeypatch)
    # Old timestamp so it's well past any cutoff.
    storage.buffer_add("old_released", "v@co.com", "s", "noise", b"X", timestamp=1.0)
    storage.buffer_add("old_held",     "v@co.com", "s", "noise", b"Y", timestamp=1.0)
    storage.buffer_mark_released("old_released")
    purged = storage.buffer_purge_expired(older_than_secs=0)   # cutoff = now
    assert purged == 1                                          # only the released one
    # The still-held row must remain — nothing held is ever purged.
    assert len(storage.buffer_list_for_recipient("v@co.com", released=0)) == 1


def test_buffer_counts_by_tier(tmp_path, monkeypatch):
    _use_tmp_db(tmp_path, monkeypatch)
    storage.buffer_add("b1", "v@co.com", "s", "noise", b"A")
    storage.buffer_add("b2", "v@co.com", "s", "noise", b"B")
    storage.buffer_add("b3", "v@co.com", "s", "uncertain", b"C")
    counts = storage.buffer_counts_by_tier("v@co.com")
    assert counts == {"noise": 2, "uncertain": 1}


def test_buffer_tier_check_constraint(tmp_path, monkeypatch):
    """The CHECK constraint rejects an invalid tier (buffer_add returns False)."""
    _use_tmp_db(tmp_path, monkeypatch)
    assert storage.buffer_add("bad", "v@co.com", "s", "garbage", b"Z") is False

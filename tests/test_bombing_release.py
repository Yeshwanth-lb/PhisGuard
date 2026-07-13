"""Tests for the bombing-buffer release worker (Phase 1B).

Guarantees: buffered mail past the analysis window is released, labeled by tier,
exactly once; recent mail is left alone; nothing is dropped. Gmail delivery is mocked.
"""
import app.layer7_gmail.smtp_receiver as rcv
import app.storage as storage


def _tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "_DB_PATH", str(tmp_path / "release.db"))
    storage.init_db()


def _mock_deliver(monkeypatch, sink):
    monkeypatch.setattr(
        "app.layer7_gmail.gmail_client.deliver_to_inbox",
        lambda settings, raw, label="": (sink.append(raw) or True),
    )


def test_release_due_delivers_labeled_and_once(tmp_path, monkeypatch):
    _tmp(tmp_path, monkeypatch)
    delivered = []
    _mock_deliver(monkeypatch, delivered)
    # timestamp=1.0 → far past the window, so both are due.
    storage.buffer_add("b1", "v@co.com", "s", "noise",
                       b"From: a@x.com\r\nSubject: Sale\r\n\r\nbody", "x.com", "Sale", timestamp=1.0)
    storage.buffer_add("b2", "v@co.com", "s", "uncertain",
                       b"From: b@y.com\r\nSubject: Hmm\r\n\r\nbody", "y.com", "Hmm", timestamp=1.0)

    n = rcv._release_due(object())
    assert n == 2
    joined = b"".join(delivered)
    assert b"[Possible Bombing Noise]" in joined       # tier 'noise' label
    assert b"[Received During Mail Bomb]" in joined     # tier 'uncertain' label

    # Released rows are not re-released, and nothing remains held.
    assert rcv._release_due(object()) == 0
    assert storage.buffer_list_for_recipient("v@co.com", released=0) == []


def test_recent_mail_not_released(tmp_path, monkeypatch):
    _tmp(tmp_path, monkeypatch)
    delivered = []
    _mock_deliver(monkeypatch, delivered)
    storage.buffer_add("b1", "v@co.com", "s", "noise", b"X", "x.com", "N")  # timestamp=now
    assert rcv._release_due(object()) == 0              # still inside the window
    assert delivered == []
    assert len(storage.buffer_list_for_recipient("v@co.com")) == 1


def test_buffer_claim_is_atomic(tmp_path, monkeypatch):
    _tmp(tmp_path, monkeypatch)
    storage.buffer_add("b1", "v@co.com", "s", "noise", b"X", timestamp=1.0)
    assert storage.buffer_claim("b1") is True    # first caller wins
    assert storage.buffer_claim("b1") is False   # second loses — already claimed


def test_buffer_unclaim_allows_reclaim(tmp_path, monkeypatch):
    _tmp(tmp_path, monkeypatch)
    storage.buffer_add("b1", "v@co.com", "s", "noise", b"X", timestamp=1.0)
    assert storage.buffer_claim("b1") is True
    storage.buffer_unclaim("b1")
    assert storage.buffer_claim("b1") is True    # claimable again after revert


def test_release_skips_already_claimed_row(tmp_path, monkeypatch):
    """A row another worker already claimed is not delivered again by us."""
    _tmp(tmp_path, monkeypatch)
    delivered = []
    _mock_deliver(monkeypatch, delivered)
    storage.buffer_add("b1", "v@co.com", "s", "noise",
                       b"From: a@x.com\r\nSubject: S\r\n\r\nb", "x.com", "S", timestamp=1.0)
    storage.buffer_claim("b1")               # simulate the other worker claiming it
    assert rcv._release_due(object()) == 0
    assert delivered == []                    # we did NOT double-deliver


def test_reclaim_stale_recovers_crashed_claim(tmp_path, monkeypatch):
    """A row claimed but never delivered (worker crashed) is reclaimed for retry."""
    _tmp(tmp_path, monkeypatch)
    storage.buffer_add("b1", "v@co.com", "s", "noise", b"X", timestamp=1.0)
    assert storage.buffer_claim("b1") is True           # claimed (delivered_at NULL)
    assert storage.buffer_claim("b1") is False           # can't double-claim
    # stale_secs=-1 makes any claim "stale" → reclaimed back to unreleased
    assert storage.buffer_reclaim_stale(-1) == 1
    assert storage.buffer_claim("b1") is True             # claimable again → not lost


def test_delivered_row_not_reclaimed(tmp_path, monkeypatch):
    _tmp(tmp_path, monkeypatch)
    storage.buffer_add("b1", "v@co.com", "s", "noise", b"X", timestamp=1.0)
    storage.buffer_claim("b1")
    storage.buffer_mark_released("b1")                    # truly delivered
    assert storage.buffer_reclaim_stale(-1) == 0          # delivered rows are never reclaimed


def test_release_recovers_then_delivers_crashed_claim(tmp_path, monkeypatch):
    """End-to-end: a crashed claim is recovered and delivered on the next cycle."""
    _tmp(tmp_path, monkeypatch)
    delivered = []
    _mock_deliver(monkeypatch, delivered)
    monkeypatch.setattr(rcv, "CLAIM_STALE_SECS", -1)      # treat the claim as stale immediately
    storage.buffer_add("b1", "v@co.com", "s", "noise",
                       b"From: a@x.com\r\nSubject: S\r\n\r\nb", "x.com", "S", timestamp=1.0)
    storage.buffer_claim("b1")                            # simulate a crash mid-delivery
    n = rcv._release_due(object())                        # next cycle reclaims + delivers
    assert n == 1
    assert delivered                                     # actually delivered, not dropped
    assert storage.buffer_list_for_recipient("v@co.com", released=0) == []


def test_release_unclaims_on_delivery_failure(tmp_path, monkeypatch):
    """If both delivery paths fail, the claim is reverted so it retries — no drop."""
    _tmp(tmp_path, monkeypatch)
    monkeypatch.setattr("app.layer7_gmail.gmail_client.deliver_to_inbox", lambda *a, **k: False)

    async def _relay_false(*a, **k):
        return False
    monkeypatch.setattr(rcv, "_relay_raw", _relay_false)

    storage.buffer_add("b1", "v@co.com", "s", "noise",
                       b"From: a@x.com\r\nSubject: S\r\n\r\nb", "x.com", "S", timestamp=1.0)
    assert rcv._release_due(object()) == 0
    held = storage.buffer_list_for_recipient("v@co.com", released=0)
    assert len(held) == 1 and held[0]["id"] == "b1"   # reverted for retry, not lost

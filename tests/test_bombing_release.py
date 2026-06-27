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

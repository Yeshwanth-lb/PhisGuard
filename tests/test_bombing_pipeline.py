"""Tests for the shared bombing pipeline (Phase 2).

evaluate() is the single entry both the SMTP gateway and the Gmail path call —
these tests prove it records arrivals, tiers under attack, and yields identical
decisions regardless of which source drove it.
"""
import app.security.bombing_pipeline as bp
import app.security.bombing_detector as bd
import app.storage as storage


def _tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "_DB_PATH", str(tmp_path / "pipeline.db"))
    storage.init_db()
    bd._state.clear()


def _parsed(domain, subject):
    return {"sender_domain": domain, "from_header": f"x@{domain}", "subject": subject,
            "sender_email": f"x@{domain}", "return_path": "", "spf_result": "unknown"}


def _raw(frm, subj, extra=b""):
    return f"From: {frm}\r\nSubject: {subj}\r\n".encode() + extra + b"\r\nbody"


def test_evaluate_not_under_attack_still_records(tmp_path, monkeypatch):
    _tmp(tmp_path, monkeypatch)
    d = bp.evaluate("v@co.com", "a@new.com", _parsed("new.com", "hi"), _raw("a@new.com", "hi"))
    assert d.under_attack is False
    assert d.action is None
    # the arrival was recorded (so the domain is now 'known')
    assert bd.is_first_contact("v@co.com", "a@new.com") is False


def test_evaluate_tiers_when_under_attack(tmp_path, monkeypatch):
    _tmp(tmp_path, monkeypatch)
    for i in range(bd.VELOCITY_THRESHOLD):
        bp.evaluate("v@co.com", f"x@d{i}.com", _parsed(f"d{i}.com", "Confirm your email"),
                    _raw(f"x@d{i}.com", "Confirm your email"))
    assert bd.is_under_attack("v@co.com")
    d = bp.evaluate("v@co.com", "news@promo.com", _parsed("promo.com", "Sale"),
                    _raw("news@promo.com", "Sale", b"List-Unsubscribe: <u@promo.com>\r\n"))
    assert d.under_attack is True
    assert d.action == "buffer"
    assert d.tier in ("noise", "uncertain")


def test_buffer_writes_durably(tmp_path, monkeypatch):
    _tmp(tmp_path, monkeypatch)
    d = bp.BombingDecision(True, False, "buffer", "noise", "[x]", None, "noise:test")
    bp.buffer(d, "v@co.com", "scan1", b"RAW", "promo.com", "Sale")
    held = storage.buffer_list_for_recipient("v@co.com")
    assert len(held) == 1 and held[0]["tier"] == "noise"


def test_identical_decisions_smtp_vs_gmail_entry(tmp_path, monkeypatch):
    """Same bomb sequence → same tier decision regardless of entry point: the logic
    lives only in the shared pipeline."""
    _tmp(tmp_path, monkeypatch)
    seq = [(f"x@d{i}.com", "Confirm your email") for i in range(bd.VELOCITY_THRESHOLD)]
    probe = ("news@promo.com", "Newsletter", b"List-Unsubscribe: <u@promo.com>\r\n")

    def run():
        bd._state.clear()
        for frm, subj in seq:
            dom = frm.split("@", 1)[1]
            bp.evaluate("v@co.com", frm, _parsed(dom, subj), _raw(frm, subj))
        d = bp.evaluate("v@co.com", probe[0], _parsed("promo.com", probe[1]),
                        _raw(probe[0], probe[1], probe[2]))
        return (d.under_attack, d.action, d.tier)

    smtp_like = run()
    gmail_like = run()
    assert smtp_like == gmail_like
    assert smtp_like == (True, "buffer", "noise")

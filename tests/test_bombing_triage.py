"""Tests for the three-tier bombing triage classifier (Phase 1B).

Tier 1 is authentication-gated (not subject-gated); structural signals drive Tier 2;
everything else falls to the Tier-3 safety valve — including a subject-only OTP from an
unauthenticated sender, which must be delivered+labeled but NEVER fast-tracked.
DKIM verification is mocked — no network.
"""
import app.security.bombing_triage as bt


def _raw(extra_headers: str = "", from_addr: str = "news@promo.com",
         subject: str = "Hello", dkim_domain: str | None = None) -> bytes:
    h = f"From: {from_addr}\r\nSubject: {subject}\r\n"
    if dkim_domain:
        h += (f"DKIM-Signature: v=1; a=rsa-sha256; d={dkim_domain}; s=sel; "
              f"h=from:subject; bh=a; b=b\r\n")
    h += extra_headers
    return (h + "\r\nbody\r\n").encode()


def _parsed(domain: str = "promo.com", subject: str = "Hello", spf: str = "unknown") -> dict:
    return {"sender_domain": domain, "from_header": f"x@{domain}",
            "subject": subject, "return_path": "", "spf_result": spf}


class TestTier1AndSpoofed:
    def test_authenticated_critical_is_tier1(self, monkeypatch):
        monkeypatch.setattr("dkim.verify", lambda *a, **k: True)
        r = bt.classify(_parsed("hdfc.bank", "Your OTP"),
                        _raw(from_addr="a@hdfc.bank", subject="Your OTP", dkim_domain="hdfc.bank"),
                        first_contact=True, trusted_domains=set())
        assert r.action == "deliver_now"
        assert r.tier == "important"
        assert r.signal == "critical"

    def test_spoofed_protected_routes_phishing(self, monkeypatch):
        """Claims .bank, DKIM fails → phishing route, never trusted (closes spoofing)."""
        monkeypatch.setattr("dkim.verify", lambda *a, **k: False)
        r = bt.classify(_parsed("hdfc.bank", "Your OTP"),
                        _raw(from_addr="a@hdfc.bank", subject="Your OTP", dkim_domain="hdfc.bank"),
                        first_contact=True, trusted_domains=set())
        assert r.action == "phishing"
        assert r.signal == "spoofed_critical"


class TestTier2Noise:
    def test_list_unsubscribe(self):
        r = bt.classify(_parsed(), _raw("List-Unsubscribe: <mailto:u@promo.com>\r\n"),
                        first_contact=False, trusted_domains=set())
        assert r.action == "buffer" and r.tier == "noise"
        assert "list_unsubscribe" in r.reason

    def test_precedence_bulk(self):
        r = bt.classify(_parsed(), _raw("Precedence: bulk\r\n"),
                        first_contact=False, trusted_domains=set())
        assert r.tier == "noise" and "bulk_or_list_id" in r.reason

    def test_list_id(self):
        r = bt.classify(_parsed(), _raw("List-Id: <promos.promo.com>\r\n"),
                        first_contact=False, trusted_domains=set())
        assert r.tier == "noise"

    def test_first_contact(self):
        r = bt.classify(_parsed(), _raw(), first_contact=True, trusted_domains=set())
        assert r.tier == "noise" and "first_contact" in r.reason

    def test_esp_fingerprint(self):
        raw = _raw("Received: from mail.mailchimp.com (1.2.3.4)\r\n")
        r = bt.classify(_parsed(), raw, first_contact=False, trusted_domains=set())
        assert r.tier == "noise" and "esp_fingerprint" in r.reason


class TestTier3SafetyValve:
    def test_ambiguous_defaults_to_uncertain_delivered(self):
        r = bt.classify(_parsed(subject="Q3 budget review"), _raw(subject="Q3 budget review"),
                        first_contact=False, trusted_domains=set())
        assert r.action == "buffer" and r.tier == "uncertain"
        assert r.reason == "uncertain:no_signal"

    def test_subject_only_otp_unauthenticated_is_tier3_not_tier1(self):
        """The throwaway-domain fake-OTP bypass: high-signal SUBJECT but no auth and no
        structural noise → Tier 3 (delivered, soft-labeled) — never fast-tracked."""
        r = bt.classify(_parsed("throwaway-xyz.com", "Your one-time code is 838201"),
                        _raw(from_addr="x@throwaway-xyz.com", subject="Your one-time code is 838201"),
                        first_contact=False, trusted_domains=set())
        assert r.action == "buffer"
        assert r.tier == "uncertain"
        assert r.signal is None
        assert "unauthenticated" in r.reason

    def test_non_english_ambiguous_is_delivered(self):
        r = bt.classify(_parsed(subject="Reunión de equipo mañana"),
                        _raw(subject="Reunion manana"),
                        first_contact=False, trusted_domains=set())
        assert r.action == "buffer" and r.tier == "uncertain"

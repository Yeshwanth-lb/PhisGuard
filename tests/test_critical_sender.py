"""Tests for the DMARC-aligned critical-sender recognizer.

A sender is Tier-1 'critical' ONLY when it is a protected type AND cryptographically
aligned (DKIM-aligned OR SPF-aligned). A protected-TLD claim that fails alignment is the
distinct 'spoofed_critical' phishing signal — never trusted. Everything fails CLOSED.

DKIM and SPF are mocked — no real network/keys are touched. DKIM is verified PER
SIGNATURE (dkim.DKIM().verify(idx)), so we mock that class to control each signature's
verification result, signing domain, and signed-headers (h=).
"""
import sys
import types

import app.security.critical_sender as cs


def _fake_spf(result="pass"):
    m = types.ModuleType("spf")
    m.check2 = lambda i, s, h: (result, "")
    return m


def _raw(from_addr: str, n_sigs: int = 0) -> bytes:
    """Build a raw message with `n_sigs` DKIM-Signature headers (content irrelevant —
    the DKIM class is mocked; only the header COUNT drives the per-signature loop)."""
    h = f"From: {from_addr}\r\n"
    for i in range(n_sigs):
        h += (f"DKIM-Signature: v=1; a=rsa-sha256; d=sig{i}.example; s=sel; "
              f"h=from:subject; bh=abc; b=def\r\n")
    h += "Subject: Your statement is ready\r\n\r\nbody\r\n"
    return h.encode()


def _install_fake_dkim(monkeypatch, sigs):
    """sigs: list of (verified: bool, signing_domain: str, h_tag: str) per signature idx."""
    import dkim

    class _FakeDKIM:
        def __init__(self, raw, *a, **k):
            self.domain = b""
            self.signature_fields = {}

        def verify(self, idx=0, **k):
            ok, dom, h = sigs[idx]
            self.domain = dom.encode()
            self.signature_fields = {b"h": h.encode()}
            return ok

    monkeypatch.setattr(dkim, "DKIM", _FakeDKIM)


def _parsed(domain: str, return_path: str = "", spf: str = "unknown") -> dict:
    return {
        "sender_domain": domain,
        "from_header": f"alerts@{domain}",
        "return_path": return_path,
        "spf_result": spf,
    }


class TestOrganizationalDomain:
    def test_simple(self):
        assert cs.organizational_domain("mail.hdfcbank.com") == "hdfcbank.com"

    def test_multi_suffix_bank_in(self):
        assert cs.organizational_domain("hdfc.bank.in") == "hdfc.bank.in"
        assert cs.organizational_domain("mail.hdfc.bank.in") == "hdfc.bank.in"

    def test_gov_in(self):
        assert cs.organizational_domain("portal.incometax.gov.in") == "incometax.gov.in"


class TestCriticalSender:
    def test_protected_tld_aligned_dkim_is_critical(self, monkeypatch):
        _install_fake_dkim(monkeypatch, [(True, "hdfc.bank", "from:subject")])
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank", 1),
                                    trusted_domains=set())
        assert res.is_critical is True and res.signal == "critical" and res.aligned is True

    def test_protected_tld_dkim_fails_is_spoofed(self, monkeypatch):
        _install_fake_dkim(monkeypatch, [(False, "hdfc.bank", "from:subject")])
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank", 1),
                                    trusted_domains=set())
        assert res.is_critical is False and res.signal == "spoofed_critical"

    def test_signing_domain_misaligned_is_spoofed(self, monkeypatch):
        _install_fake_dkim(monkeypatch, [(True, "attacker.com", "from:subject")])
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank", 1),
                                    trusted_domains=set())
        assert res.is_critical is False and res.signal == "spoofed_critical"

    def test_multi_signature_spoof_is_rejected(self, monkeypatch):
        """THE bypass: a valid throwaway sig (idx0) + a bogus d=<victim> sig (idx1).
        Only the verified sig's d= may be trusted, and it doesn't align → spoofed."""
        _install_fake_dkim(monkeypatch, [
            (True,  "attacker.com", "from:subject"),   # verifies, but not aligned
            (False, "hdfc.bank",    "from:subject"),   # claims victim, does NOT verify
        ])
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank", 2),
                                    trusted_domains=set())
        assert res.is_critical is False and res.signal == "spoofed_critical"

    def test_aligned_but_from_not_signed_is_spoofed(self, monkeypatch):
        """Verified + aligned d=, but the signature does not cover From → meaningless."""
        _install_fake_dkim(monkeypatch, [(True, "hdfc.bank", "subject:date")])
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank", 1),
                                    trusted_domains=set())
        assert res.is_critical is False and res.signal == "spoofed_critical"

    def test_no_raw_fails_closed(self):
        res = cs.is_critical_sender(_parsed("treasury.gov"), None, trusted_domains=set())
        assert res.is_critical is False and res.signal == "spoofed_critical"

    def test_dkim_verify_raises_fails_closed(self, monkeypatch):
        import dkim

        class _BoomDKIM:
            def __init__(self, raw, *a, **k): pass
            def verify(self, idx=0, **k): raise RuntimeError("dns timeout")
        monkeypatch.setattr(dkim, "DKIM", _BoomDKIM)
        res = cs.is_critical_sender(_parsed("x.bank"), _raw("a@x.bank", 1), trusted_domains=set())
        assert res.is_critical is False and res.signal == "spoofed_critical"

    def test_non_protected_domain_is_not_critical(self, monkeypatch):
        _install_fake_dkim(monkeypatch, [(True, "example.com", "from")])
        res = cs.is_critical_sender(_parsed("newsletter.example.com"),
                                    _raw("a@newsletter.example.com", 1), trusted_domains=set())
        assert res.is_critical is False and res.signal is None

    def test_trusted_table_domain_aligned_is_critical(self, monkeypatch):
        _install_fake_dkim(monkeypatch, [(True, "mycreditunion.com", "from")])
        res = cs.is_critical_sender(_parsed("mycreditunion.com"),
                                    _raw("a@mycreditunion.com", 1),
                                    trusted_domains={"mycreditunion.com"})
        assert res.is_critical is True and res.signal == "critical"

    def test_trusted_table_domain_unaligned_is_spoofed(self, monkeypatch):
        _install_fake_dkim(monkeypatch, [(False, "mycreditunion.com", "from")])
        res = cs.is_critical_sender(_parsed("mycreditunion.com"),
                                    _raw("a@mycreditunion.com", 1),
                                    trusted_domains={"mycreditunion.com"})
        assert res.is_critical is False and res.signal == "spoofed_critical"


class TestSpfAlignment:
    """SPF path: trust = DKIM-aligned OR SPF-aligned (real DMARC alignment)."""

    def test_spf_aligned_grants_tier1_without_dkim(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "spf", _fake_spf("pass"))
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank", 0),
                                    trusted_domains=set(), peer_ip="203.0.113.5",
                                    envelope_from="bounce@hdfc.bank")
        assert res.is_critical is True and res.signal == "critical"
        assert res.detail["spf_aligned"] is True and res.detail["dkim_aligned"] is False

    def test_spf_pass_but_not_aligned_is_spoofed(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "spf", _fake_spf("pass"))
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank", 0),
                                    trusted_domains=set(), peer_ip="203.0.113.5",
                                    envelope_from="bounce@random-mailer.com")
        assert res.is_critical is False and res.signal == "spoofed_critical"
        assert res.detail["spf_aligned"] is False

    def test_spf_softfail_is_spoofed(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "spf", _fake_spf("softfail"))
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank", 0),
                                    trusted_domains=set(), peer_ip="203.0.113.5",
                                    envelope_from="bounce@hdfc.bank")
        assert res.is_critical is False and res.signal == "spoofed_critical"

    def test_spf_skipped_without_peer_ip(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "spf", _fake_spf("pass"))
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank", 0),
                                    trusted_domains=set(), peer_ip=None,
                                    envelope_from="bounce@hdfc.bank")
        assert res.is_critical is False and res.detail["spf_aligned"] is False

    def test_dkim_wins_even_if_spf_fails(self, monkeypatch):
        _install_fake_dkim(monkeypatch, [(True, "hdfc.bank", "from:subject")])
        monkeypatch.setitem(sys.modules, "spf", _fake_spf("fail"))
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank", 1),
                                    trusted_domains=set(), peer_ip="203.0.113.5",
                                    envelope_from="bounce@hdfc.bank")
        assert res.is_critical is True   # DKIM-aligned OR SPF-aligned

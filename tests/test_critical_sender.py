"""Tests for the DMARC-aligned critical-sender recognizer (Phase 1A).

The throughline: a sender is Tier-1 'critical' ONLY when it is a protected type AND
cryptographically aligned. A protected-TLD claim that fails alignment is the distinct
'spoofed_critical' phishing signal — never trusted. Everything fails CLOSED.

DKIM verification is mocked — no real network/keys are touched.
"""
import sys
import types

import app.security.critical_sender as cs


def _fake_spf(result="pass"):
    m = types.ModuleType("spf")
    m.check2 = lambda i, s, h: (result, "")
    return m


def _raw(from_addr: str, dkim_domain: str | None = None) -> bytes:
    h = f"From: {from_addr}\r\n"
    if dkim_domain:
        h += (f"DKIM-Signature: v=1; a=rsa-sha256; d={dkim_domain}; s=sel; "
              f"h=from:subject; bh=abc; b=def\r\n")
    h += "Subject: Your statement is ready\r\n\r\nbody\r\n"
    return h.encode()


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
        """Protected TLD + DKIM verifies + signing domain aligns → Tier 1."""
        monkeypatch.setattr("dkim.verify", lambda *a, **k: True)
        res = cs.is_critical_sender(
            _parsed("hdfc.bank"), _raw("a@hdfc.bank", dkim_domain="hdfc.bank"),
            trusted_domains=set(),
        )
        assert res.is_critical is True
        assert res.signal == "critical"
        assert res.aligned is True

    def test_protected_tld_dkim_fails_is_spoofed(self, monkeypatch):
        """Claims .bank but the DKIM signature does not verify → spoofed_critical."""
        monkeypatch.setattr("dkim.verify", lambda *a, **k: False)
        res = cs.is_critical_sender(
            _parsed("hdfc.bank"), _raw("a@hdfc.bank", dkim_domain="hdfc.bank"),
            trusted_domains=set(),
        )
        assert res.is_critical is False
        assert res.signal == "spoofed_critical"

    def test_protected_tld_signing_domain_misaligned_is_spoofed(self, monkeypatch):
        """DKIM verifies but signs as attacker.com (not aligned to From) → spoofed."""
        monkeypatch.setattr("dkim.verify", lambda *a, **k: True)
        res = cs.is_critical_sender(
            _parsed("hdfc.bank"), _raw("a@hdfc.bank", dkim_domain="attacker.com"),
            trusted_domains=set(),
        )
        assert res.is_critical is False
        assert res.signal == "spoofed_critical"

    def test_protected_tld_no_raw_fails_closed(self):
        """No raw message to verify → cannot align → spoofed_critical (fail-closed)."""
        res = cs.is_critical_sender(_parsed("treasury.gov"), None, trusted_domains=set())
        assert res.is_critical is False
        assert res.signal == "spoofed_critical"

    def test_dkim_verify_raises_fails_closed(self, monkeypatch):
        def _boom(*a, **k):
            raise RuntimeError("dns timeout")
        monkeypatch.setattr("dkim.verify", _boom)
        res = cs.is_critical_sender(
            _parsed("x.bank"), _raw("a@x.bank", dkim_domain="x.bank"),
            trusted_domains=set(),
        )
        assert res.is_critical is False
        assert res.signal == "spoofed_critical"

    def test_non_protected_domain_is_not_critical(self, monkeypatch):
        """An ordinary domain is neither critical nor spoofed — just not protected."""
        monkeypatch.setattr("dkim.verify", lambda *a, **k: True)
        res = cs.is_critical_sender(
            _parsed("newsletter.example.com"),
            _raw("a@newsletter.example.com", dkim_domain="example.com"),
            trusted_domains=set(),
        )
        assert res.is_critical is False
        assert res.signal is None

    def test_trusted_table_domain_aligned_is_critical(self, monkeypatch):
        """Domain in the trusted_domains table (not a protected TLD) + aligned → Tier 1."""
        monkeypatch.setattr("dkim.verify", lambda *a, **k: True)
        res = cs.is_critical_sender(
            _parsed("mycreditunion.com"),
            _raw("a@mycreditunion.com", dkim_domain="mycreditunion.com"),
            trusted_domains={"mycreditunion.com"},
        )
        assert res.is_critical is True
        assert res.signal == "critical"

    def test_trusted_table_domain_unaligned_is_spoofed(self, monkeypatch):
        monkeypatch.setattr("dkim.verify", lambda *a, **k: False)
        res = cs.is_critical_sender(
            _parsed("mycreditunion.com"),
            _raw("a@mycreditunion.com", dkim_domain="mycreditunion.com"),
            trusted_domains={"mycreditunion.com"},
        )
        assert res.is_critical is False
        assert res.signal == "spoofed_critical"


class TestSpfAlignment:
    """SPF path: trust = DKIM-aligned OR SPF-aligned (real DMARC alignment)."""

    def test_spf_aligned_grants_tier1_without_dkim(self, monkeypatch):
        monkeypatch.setattr("dkim.verify", lambda *a, **k: False)   # no DKIM
        monkeypatch.setitem(sys.modules, "spf", _fake_spf("pass"))
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank"),
                                    trusted_domains=set(), peer_ip="203.0.113.5",
                                    envelope_from="bounce@hdfc.bank")
        assert res.is_critical is True and res.signal == "critical"
        assert res.detail["spf_aligned"] is True and res.detail["dkim_aligned"] is False

    def test_spf_pass_but_not_aligned_is_spoofed(self, monkeypatch):
        """spf=pass on a NON-aligned envelope domain must not grant trust."""
        monkeypatch.setattr("dkim.verify", lambda *a, **k: False)
        monkeypatch.setitem(sys.modules, "spf", _fake_spf("pass"))
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank"),
                                    trusted_domains=set(), peer_ip="203.0.113.5",
                                    envelope_from="bounce@random-mailer.com")
        assert res.is_critical is False and res.signal == "spoofed_critical"
        assert res.detail["spf_aligned"] is False

    def test_spf_softfail_is_spoofed(self, monkeypatch):
        monkeypatch.setattr("dkim.verify", lambda *a, **k: False)
        monkeypatch.setitem(sys.modules, "spf", _fake_spf("softfail"))
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank"),
                                    trusted_domains=set(), peer_ip="203.0.113.5",
                                    envelope_from="bounce@hdfc.bank")
        assert res.is_critical is False and res.signal == "spoofed_critical"

    def test_spf_skipped_without_peer_ip(self, monkeypatch):
        """No peer IP (e.g. Gmail-ingested mail) → SPF can't run; DKIM alone decides."""
        monkeypatch.setattr("dkim.verify", lambda *a, **k: False)
        monkeypatch.setitem(sys.modules, "spf", _fake_spf("pass"))
        res = cs.is_critical_sender(_parsed("hdfc.bank"), _raw("a@hdfc.bank"),
                                    trusted_domains=set(), peer_ip=None,
                                    envelope_from="bounce@hdfc.bank")
        assert res.is_critical is False and res.detail["spf_aligned"] is False

    def test_dkim_wins_even_if_spf_fails(self, monkeypatch):
        monkeypatch.setattr("dkim.verify", lambda *a, **k: True)
        monkeypatch.setitem(sys.modules, "spf", _fake_spf("fail"))
        res = cs.is_critical_sender(_parsed("hdfc.bank"),
                                    _raw("a@hdfc.bank", dkim_domain="hdfc.bank"),
                                    trusted_domains=set(), peer_ip="203.0.113.5",
                                    envelope_from="bounce@hdfc.bank")
        assert res.is_critical is True   # DKIM-aligned OR SPF-aligned

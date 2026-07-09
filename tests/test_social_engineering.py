"""Plain-text social-engineering detection (structural lexical signal + rung)."""
import asyncio
from unittest.mock import patch

from app.layer2_ai import orchestrator
from app.layer2_ai.structural import _social_engineering_score as se


class TestSocialEngineeringScore:
    def test_advance_fee_419(self):
        s, cats = se("Business proposal",
                     "the Central Bank of Nigeria. abandoned sum of US$37,400,000 "
                     "belonging to a late customer. I need you as next of kin.")
        assert s >= 0.45 and "advance_fee" in cats

    def test_lottery(self):
        s, cats = se("WINNING NOTIFICATION",
                     "You have won the national lottery. Dear lucky winner, claim your prize.")
        assert s >= 0.45 and "prize_lottery" in cats

    def test_loan_scam(self):
        s, cats = se("Pre-Approved",
                     "your application was approved. You are eligible for $500,000 with a low rate.")
        assert s >= 0.45 and "loan_refi" in cats

    def test_bec_bank_change_single_signal_fires(self):
        # BEC bank-detail diversion is high-specificity — a single match must fire.
        s, cats = se("Vendor update", "Per finance, our bank details have changed. "
                                       "Please update your banking information.")
        assert s >= 0.45 and "bec_diversion" in cats

    # ── benign must NOT fire ──
    def test_benign_business(self):
        assert se("Q3 review", "following up on the Q3 partnership numbers, can we sync?")[0] == 0.0

    def test_benign_status(self):
        assert se("Phoenix status", "Phoenix is green. Milestone 3 shipped Monday.")[0] == 0.0

    def test_bare_wire_transfer_does_not_fire(self):
        # A single medium-specificity phrase in otherwise-legit mail must stay silent.
        assert se("Invoice", "Please process the wire transfer for invoice 4432 by Friday.")[0] == 0.0

    def test_empty(self):
        assert se("", "")[0] == 0.0


class TestSocialEngineeringRung:
    """The orchestrator must escalate scam-language mail to suspicious even when
    NLP under-reads and the domain is clean (composite would dilute to clean)."""

    def test_rung_fires_when_nlp_underreads(self):
        async def fake_structural(parsed):
            return {"engine": "structural", "score": 0.53, "findings": ["social_engineering:advance_fee"],
                    "social_engineering_score": 0.53, "social_engineering_categories": ["advance_fee"]}
        async def fake_nlp(parsed, **kw):
            return {"engine": "nlp", "score": 0.2}
        async def fake_behavioral(parsed, **kw):
            return {"engine": "behavioral", "score": 0.1}

        with patch.object(orchestrator, "run_structural", fake_structural), \
             patch.object(orchestrator, "run_nlp", fake_nlp), \
             patch.object(orchestrator, "run_behavioral", fake_behavioral), \
             patch.object(orchestrator, "LLMClient", lambda s: type("C", (), {"provider": "x"})()):
            r = asyncio.run(orchestrator.run_layer2({"sender_domain": "x.com"}, object()))
        assert r["verdict"] == "suspicious"
        assert r["triggered_tier"] == "struct_socialeng"

    def test_no_false_escalation_when_all_low(self):
        async def fake_structural(parsed):
            return {"engine": "structural", "score": 0.0, "findings": [],
                    "social_engineering_score": 0.0, "social_engineering_categories": []}
        async def fake_nlp(parsed, **kw):
            return {"engine": "nlp", "score": 0.1}
        async def fake_behavioral(parsed, **kw):
            return {"engine": "behavioral", "score": 0.1}

        with patch.object(orchestrator, "run_structural", fake_structural), \
             patch.object(orchestrator, "run_nlp", fake_nlp), \
             patch.object(orchestrator, "run_behavioral", fake_behavioral), \
             patch.object(orchestrator, "LLMClient", lambda s: type("C", (), {"provider": "x"})()):
            r = asyncio.run(orchestrator.run_layer2({"sender_domain": "x.com"}, object()))
        assert r["verdict"] == "clean"


class TestBecOpener:
    """Executive-impersonation BEC openers: free-webmail sender + >=2 BEC markers."""

    def _s(self, frm, dom, subj, body, rt=""):
        from app.layer2_ai.structural import _bec_opener_score
        return _bec_opener_score(frm, dom, rt, subj, body)

    def test_ceo_fraud_availability_probe_fires(self):
        s, m = self._s("ceo.michael.tan@gmail.com", "gmail.com",
                       "Quick task - are you available?",
                       "are you at your desk? I need you to handle something urgent "
                       "and discreet. Sent from my iPhone")
        assert s >= 0.45 and len(m) >= 2

    def test_gift_card_scam_fires(self):
        s, m = self._s("j.wilson.exec@outlook.com", "outlook.com", "Favor needed",
                       "I need you to purchase Apple gift cards, scratch the back and "
                       "email me the codes. I'll reimburse you. Keep this between us.")
        assert s >= 0.45 and "giftcard_wire" in m

    def test_legit_gmail_personal_does_not_fire(self):
        # one marker (availability), no urgency/secrecy/authority/giftcard -> silent
        s, _ = self._s("friend@gmail.com", "gmail.com", "Lunch?",
                       "Hey are you free for lunch tomorrow at 1?")
        assert s == 0.0

    def test_corporate_sender_does_not_fire(self):
        # real boss on the corporate domain: has markers but not free-webmail -> silent
        s, _ = self._s("boss@company.com", "company.com", "Handle the report",
                       "I need you to handle the Q3 report right away, it's urgent.")
        assert s == 0.0

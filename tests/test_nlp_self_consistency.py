"""NLP self-consistency voting — median-of-N sampling to reduce verdict drift."""
import asyncio


class _FakeClient:
    provider = "claude"
    model = "claude-opus-4-7"
    is_ai_powered = True

    def __init__(self, scores):
        self._scores = scores
        self.calls = 0

    async def complete(self, system_prompt, user, max_tokens=1024):
        s = self._scores[self.calls % len(self._scores)]
        self.calls += 1
        return ('{"phishing_score": %s, "intent": "t", "tactics": ["x"], "reasoning": "r"}' % s)


_PARSED = {"subject": "x", "body_text": "y", "from_header": "a@b.com"}


def _run(client, n):
    from app.layer2_ai.nlp_engine import run_nlp

    class S:
        nlp_self_consistency_samples = n
    return asyncio.run(run_nlp(_PARSED, llm_client=client, settings=S()))


def test_default_single_call():
    c = _FakeClient([0.3])
    r = _run(c, 1)
    assert c.calls == 1               # no extra cost by default
    assert r["score"] == 0.3


def test_median_of_three():
    c = _FakeClient([0.3, 0.9, 0.6])  # median = 0.6
    r = _run(c, 3)
    assert c.calls == 3
    assert r["score"] == 0.6


def test_median_of_five():
    c = _FakeClient([0.1, 0.2, 0.5, 0.8, 0.9])  # median = 0.5
    r = _run(c, 5)
    assert c.calls == 5
    assert r["score"] == 0.5


def test_returned_sample_is_internally_consistent():
    # The returned dict must be the median SAMPLE whole, not a frankenstein —
    # score/intent/reasoning all come from the same call.
    c = _FakeClient([0.2, 0.7, 0.4])  # median 0.4
    r = _run(c, 3)
    assert r["score"] == 0.4
    assert r["intent"] == "t" and "reasoning" in r

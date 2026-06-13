"""Engine 3 — Behavioral Anomaly Detector (3-tier cold start)."""
import hashlib
import json
import os
import structlog
from typing import Optional
from datetime import datetime, timezone

logger = structlog.get_logger()

BASELINE_DIR = os.path.join("ml", "baselines")


def _sender_key(email: str) -> str:
    return hashlib.md5(email.encode()).hexdigest()


def _load_baseline(email: str) -> Optional[dict]:
    os.makedirs(BASELINE_DIR, exist_ok=True)
    path = os.path.join(BASELINE_DIR, _sender_key(email) + ".json")
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return None


def _save_baseline(email: str, data: dict) -> None:
    os.makedirs(BASELINE_DIR, exist_ok=True)
    path = os.path.join(BASELINE_DIR, _sender_key(email) + ".json")
    with open(path, "w") as f:
        json.dump(data, f)


def _update_baseline(baseline: dict, parsed: dict) -> dict:
    baseline["email_count"] = baseline.get("email_count", 0) + 1
    return baseline


async def run_behavioral(parsed: dict) -> dict:
    """
    Engine 3: Behavioral Anomaly Detector.
    Tier 1 (no sender)   -> neutral 0.2
    Tier 2 (new sender)  -> neutral 0.2, create baseline
    Tier 3 (known)       -> compare against baseline
    """
    sender_email  = parsed.get("sender_email", "") or ""
    sender_domain = parsed.get("sender_domain", "") or ""

    if not sender_email:
        return {"engine": "behavioral", "score": 0.2, "reason": "no_sender", "is_new_sender": True}

    baseline = _load_baseline(sender_email)
    if baseline is None:
        new_bl = {
            "email_count": 1,
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "sender_domain": sender_domain,
        }
        _save_baseline(sender_email, new_bl)
        return {"engine": "behavioral", "score": 0.2, "reason": "new_sender", "is_new_sender": True}

    score = 0.0
    reasons = []

    if baseline.get("sender_domain") and baseline["sender_domain"] != sender_domain:
        score += 0.5
        reasons.append("sender_domain_changed")

    prior_count = baseline.get("email_count", 0)
    if prior_count < 3:
        score += 0.2
        reasons.append(f"low_prior_count:{prior_count}")

    final = min(score, 1.0)
    _save_baseline(sender_email, _update_baseline(baseline, parsed))
    logger.info("behavioral_done", score=round(final, 3), reasons=reasons)
    return {
        "engine": "behavioral",
        "score": round(final, 3),
        "reason": "; ".join(reasons) if reasons else "normal",
        "is_new_sender": False,
    }

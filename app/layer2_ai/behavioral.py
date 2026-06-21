"""Engine 3 — Behavioral Anomaly Detector (3-tier cold start architecture).

Tier 0 (0 emails):    0.60 × context_score  + 0.40 × iso_score
Tier 1 (1–5 emails):  0.50 × context_score  + 0.50 × iso_score
Tier 2 (6–19 emails): 0.40 × iso_score      + 0.60 × simplified_gmm_score
Tier 3 (20+ emails):  per_sender_gmm_score

The Context Scorer is deterministic — no training data required.
The Global Isolation Forest provides population-level anomaly detection.
The per-sender Gaussian/GMM provides fine-grained baseline deviation scoring.
"""
import hashlib
import json
import math
import os
import pickle
from datetime import UTC, datetime

import structlog

logger = structlog.get_logger()

BASELINE_DIR = os.path.join("ml", "baselines")
_ISO_MODEL_PATH_DEFAULT = os.path.join("models", "global_iso_v1.pkl")

# Feature dimension for the Isolation Forest / GMM vectors
_FEAT_DIM = 8

# --- Internal state for the global Isolation Forest ---
_iso_model = None            # sklearn IsolationForest instance or None
_iso_model_path = None       # path the model was loaded from
_iso_sample_count = 0        # how many feature vectors have been accumulated
_iso_pending_vectors: list   = []   # accumulated since last retrain


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _extract_feature_vector(parsed: dict) -> list[float]:
    """Return a fixed-length numeric feature vector from a parsed email dict."""
    body_text = parsed.get("body_text", "") or ""
    body_html = parsed.get("body_html", "") or ""
    urls = parsed.get("urls", parsed.get("attachment_hashes", [])) or []
    attachments = parsed.get("attachments", []) or []
    spf_ok = 1.0 if parsed.get("spf_result") == "pass" else 0.0
    dkim_ok = 1.0 if parsed.get("dkim_result") == "pass" else 0.0
    dmarc_ok = 1.0 if parsed.get("dmarc_result") == "pass" else 0.0
    auth_fail_count = 3.0 - (spf_ok + dkim_ok + dmarc_ok)
    return [
        min(len(body_text) / 2000.0, 1.0),         # 0: body length (normalised)
        min(len(urls) / 10.0, 1.0),                 # 1: URL count
        min(len(attachments) / 5.0, 1.0),           # 2: attachment count
        1.0 if body_html else 0.0,                  # 3: has HTML body
        1.0 if parsed.get("reply_to") else 0.0,     # 4: has Reply-To header
        auth_fail_count / 3.0,                      # 5: auth failure rate
        min(len(parsed.get("subject", "") or "") / 100.0, 1.0),  # 6: subject length
        1.0 if parsed.get("return_path") else 0.0,  # 7: has Return-Path
    ]


# ---------------------------------------------------------------------------
# Baseline persistence (per-sender JSON files)
# ---------------------------------------------------------------------------

def _sender_key(email: str) -> str:
    return hashlib.md5(email.encode()).hexdigest()


def _load_baseline(email: str) -> dict | None:
    os.makedirs(BASELINE_DIR, exist_ok=True)
    path = os.path.join(BASELINE_DIR, _sender_key(email) + ".json")
    if os.path.exists(path):
        try:
            with open(path) as fh:
                return json.load(fh)
        except Exception:
            pass
    return None


def _save_baseline(email: str, data: dict) -> None:
    """Write baseline atomically using a temp file + rename to avoid partial writes
    and to prevent data loss from concurrent requests for the same sender."""
    os.makedirs(BASELINE_DIR, exist_ok=True)
    path = os.path.join(BASELINE_DIR, _sender_key(email) + ".json")
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp_path, path)   # atomic on POSIX; near-atomic on Windows
    except Exception as exc:
        logger.warning("baseline_save_err", error=str(exc))
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


def _extract_send_hour(parsed: dict) -> int | None:
    """Extract the hour (0-23) the email was sent from the Date: header."""
    headers = parsed.get("headers") or {}
    date_str = headers.get("Date", "") or parsed.get("date", "")
    if not date_str:
        # Try Received headers as fallback
        received = headers.get("Received", []) or []
        if isinstance(received, list) and received:
            date_str = str(received[0])
    if not date_str:
        return None
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(str(date_str))
        return dt.hour
    except Exception:
        pass
    # Fallback: regex for HH:MM:SS pattern
    import re
    m = re.search(r"\b(\d{2}):\d{2}:\d{2}\b", str(date_str))
    if m:
        return int(m.group(1))
    return None


def _update_baseline(baseline: dict, parsed: dict) -> dict:
    fv = _extract_feature_vector(parsed)
    baseline["email_count"] = baseline.get("email_count", 0) + 1
    baseline["last_updated"] = datetime.now(UTC).isoformat()

    # Accumulate real send hours from Date: header
    hours = baseline.get("send_hours", [])
    send_hour = _extract_send_hour(parsed)
    if send_hour is not None:
        hours.append(send_hour)
    baseline["send_hours"] = hours[-100:]  # keep last 100

    # Track known domains
    known = set(baseline.get("known_domains", []))
    for url in (parsed.get("urls") or []):
        try:
            from urllib.parse import urlparse as _up
            d = _up(url).netloc.lower()
            if d:
                known.add(d)
        except Exception:
            pass
    baseline["known_domains"] = list(known)[:200]

    # Track body length running average
    n = baseline["email_count"]
    old_avg = baseline.get("avg_body_length", 0.0)
    body_len = len(parsed.get("body_text", "") or "")
    baseline["avg_body_length"] = old_avg + (body_len - old_avg) / n

    # Store last 50 feature vectors for GMM training
    vecs = baseline.get("feature_vectors", [])
    vecs.append(fv)
    baseline["feature_vectors"] = vecs[-50:]

    return baseline


def _new_baseline(email: str, sender_domain: str, parsed: dict) -> dict:
    return {
        "email_count": 1,
        "first_seen": datetime.now(UTC).isoformat(),
        "last_updated": datetime.now(UTC).isoformat(),
        "sender_domain": sender_domain,
        "send_hours": [12],
        "avg_body_length": len(parsed.get("body_text", "") or ""),
        "known_domains": [],
        "feature_vectors": [_extract_feature_vector(parsed)],
    }


# ---------------------------------------------------------------------------
# Context Scorer (Tier 0 & Tier 1) — deterministic, no training data needed
# ---------------------------------------------------------------------------

_DEFAULT_HIGH_VALUE_ROLES = {
    "cfo", "ceo", "cto", "ciso", "finance", "payroll",
    "hr", "legal", "accounting", "treasury",
}


def _context_score(parsed: dict, baseline: dict | None, settings=None) -> float:
    """Deterministic risk score based on observable email facts at parse time."""
    score = 0.0
    high_value = (
        getattr(settings, "cold_high_value_role_list", None) or list(_DEFAULT_HIGH_VALUE_ROLES)
    )
    high_value_set = {r.lower() for r in high_value}

    # Recipient is a high-value target
    headers = parsed.get("headers", {}) or {}
    to_field = str(headers.get("To", "") or "").lower()
    subject = (parsed.get("subject", "") or "").lower()
    if any(role in to_field or role in subject for role in high_value_set):
        score += 0.30

    # First ever email from this sender
    if baseline is None or baseline.get("email_count", 0) <= 1:
        score += 0.15

    # Off-hours send (very approximate — no reliable send time in parsed dict yet)
    # We placeholder this as 0 because we don't extract send_hour from Received headers yet
    # score += 0.10 if off_hours else 0.0

    # New domain links (all URLs go to domains not seen from this sender before)
    urls = parsed.get("urls") or []
    if urls and baseline:
        known_doms = set(baseline.get("known_domains", []))
        if known_doms:
            new_doms = 0
            for url in urls[:10]:
                try:
                    from urllib.parse import urlparse as _up
                    d = _up(url).netloc.lower()
                    if d and d not in known_doms:
                        new_doms += 1
                except Exception:
                    pass
            if new_doms > 0 and new_doms == len(urls[:10]):
                score += 0.10

    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Global Isolation Forest (Tiers 0, 1, 2)
# ---------------------------------------------------------------------------

def _get_iso_model_path(settings=None) -> str:
    if settings:
        p = getattr(settings, "l2_global_iso_model_path", None)
        if p:
            return p
    return _ISO_MODEL_PATH_DEFAULT


def _load_iso_model(path: str):
    global _iso_model, _iso_model_path
    if _iso_model is not None and _iso_model_path == path:
        return _iso_model
    if os.path.exists(path):
        try:
            with open(path, "rb") as fh:
                _iso_model = pickle.load(fh)
                _iso_model_path = path
                return _iso_model
        except Exception as exc:
            logger.warning("iso_load_err", error=str(exc))
    return None


def _save_iso_model(model, path: str) -> None:
    global _iso_model, _iso_model_path
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as fh:
            pickle.dump(model, fh)
        _iso_model = model
        _iso_model_path = path
    except Exception as exc:
        logger.warning("iso_save_err", error=str(exc))


def _iso_score(fv: list[float], settings=None) -> float:
    """Return anomaly score from global Isolation Forest. 0=normal, 1=anomalous."""
    global _iso_pending_vectors, _iso_sample_count

    min_samples = getattr(settings, "l2_global_iso_min_samples", 50) if settings else 50
    retrain_interval = getattr(settings, "l2_global_iso_retrain_interval", 500) if settings else 500
    model_path = _get_iso_model_path(settings)

    _iso_pending_vectors.append(fv)
    _iso_sample_count += 1

    # Retrain the model if we have enough new data
    if _iso_sample_count % retrain_interval == 0 and _iso_sample_count >= min_samples:
        _retrain_iso(model_path, settings)

    model = _load_iso_model(model_path)
    if model is None or _iso_sample_count < min_samples:
        return 0.5  # neutral until enough data

    try:
        import numpy as np
        x = np.array(fv).reshape(1, -1)
        # IsolationForest.score_samples returns negative anomaly scores
        # -0.5 = typical, -1.0 = very anomalous; we convert to 0-1 where 1=anomalous
        raw = float(model.score_samples(x)[0])
        # Typically ranges from about -0.8 to -0.3; map to 0–1 linearly
        score = max(0.0, min(1.0, (-raw - 0.3) / 0.5))
        return round(score, 4)
    except Exception as exc:
        logger.warning("iso_score_err", error=str(exc))
        return 0.5


def _retrain_iso(model_path: str, settings=None) -> None:
    global _iso_pending_vectors
    vectors = list(_iso_pending_vectors)
    if len(vectors) < 50:
        return
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest

        X = np.array(vectors)
        model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        model.fit(X)
        _save_iso_model(model, model_path)
        logger.info("iso_retrained", n_samples=len(vectors))
    except Exception as exc:
        logger.warning("iso_retrain_err", error=str(exc))


# ---------------------------------------------------------------------------
# Per-sender Gaussian scorer (Tiers 2 and 3)
# ---------------------------------------------------------------------------

def _gaussian_score(fv: list[float], baseline: dict) -> float:
    """Score anomaly against the per-sender distribution.

    Uses a simple multivariate Gaussian (mean + variance per dimension).
    Returns 0 = very normal, 1 = very anomalous.
    """
    vecs = baseline.get("feature_vectors", [])
    n = len(vecs)
    if n < 3:
        return 0.5

    try:
        import numpy as np

        X = np.array(vecs, dtype=float)  # shape (n, dim)
        x = np.array(fv, dtype=float)

        mu = X.mean(axis=0)
        sigma = X.std(axis=0) + 1e-6  # add epsilon to avoid div-by-zero

        # Normalised Euclidean distance (z-score per dimension, then L2 norm)
        z = (x - mu) / sigma
        dist = float(np.sqrt(np.mean(z ** 2)))

        # Map distance to 0-1: dist=0 → score=0, dist≥3 → score≈1
        score = 1.0 - math.exp(-dist / 2.0)
        return round(min(max(score, 0.0), 1.0), 4)
    except Exception as exc:
        logger.warning("gmm_score_err", error=str(exc))
        return 0.5


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_behavioral(parsed: dict, settings=None) -> dict:
    """Engine 3: Behavioral Anomaly Detector — 3-tier cold start."""
    sender_email = parsed.get("sender_email", "") or ""
    sender_domain = parsed.get("sender_domain", "") or ""

    if not sender_email:
        return {
            "engine": "behavioral",
            "score": 0.2,
            "reason": "no_sender",
            "is_new_sender": True,
            "cold_start_tier": 0,
            "baseline_confidence": "none",
            "emails_in_baseline": 0,
            "deviation_dimensions": {
                "timing": 0.0, "vocabulary": 0.0,
                "recipient_graph": 0.0, "domain_links": 0.0,
            },
            "dominant_deviation": "none",
        }

    baseline = _load_baseline(sender_email)
    email_count = (baseline or {}).get("email_count", 0)

    # Determine tier
    if email_count == 0:
        tier = 0
    elif email_count <= 5:
        tier = 1
    elif email_count <= 19:
        tier = 2
    else:
        tier = 3

    fv = _extract_feature_vector(parsed)
    ctx = _context_score(parsed, baseline, settings)
    iso = _iso_score(fv, settings)
    gmm = _gaussian_score(fv, baseline) if baseline else 0.5

    # Tier blending
    if tier == 0:
        final = 0.60 * ctx + 0.40 * iso
        baseline_confidence = "none"
    elif tier == 1:
        final = 0.50 * ctx + 0.50 * iso
        baseline_confidence = "low"
    elif tier == 2:
        final = 0.40 * iso + 0.60 * gmm
        baseline_confidence = "medium"
    else:
        final = gmm
        baseline_confidence = "high"

    final = round(min(max(final, 0.0), 1.0), 4)

    # Deviation dimensions (best-effort from available data)
    known_domains = set((baseline or {}).get("known_domains", []))
    url_domains: set = set()
    for url in (parsed.get("urls") or []):
        try:
            from urllib.parse import urlparse as _up
            d = _up(url).netloc.lower()
            if d:
                url_domains.add(d)
        except Exception:
            pass
    domain_links_dev = 0.8 if (url_domains - known_domains) else 0.0

    vocab_dev = round(max(0.0, gmm - 0.3), 4) if tier >= 2 else 0.0
    recipient_dev = 0.3 if (baseline is None or email_count < 3) else 0.0

    # Timing deviation: compare current send hour to sender's historical hours
    timing_dev = 0.0
    send_hour = _extract_send_hour(parsed)
    if send_hour is not None and baseline:
        hist_hours = baseline.get("send_hours", [])
        if len(hist_hours) >= 3:
            import statistics
            try:
                mean_h = statistics.mean(hist_hours)
                std_h  = statistics.stdev(hist_hours) + 1e-6
                z = abs(send_hour - mean_h) / std_h
                # Outside 08:00-18:00 AND unusual for this sender → flag
                is_off_hours = send_hour < 8 or send_hour > 18
                timing_dev = round(min((z / 4.0) + (0.15 if is_off_hours else 0.0), 1.0), 4)
            except Exception:
                pass

    dims = {
        "timing": timing_dev,
        "vocabulary": vocab_dev,
        "recipient_graph": recipient_dev,
        "domain_links": round(domain_links_dev, 4),
    }
    dominant = max(dims, key=dims.get)  # type: ignore
    if dims[dominant] == 0.0:
        dominant = "none"

    # Update baseline
    if baseline is None:
        baseline = _new_baseline(sender_email, sender_domain, parsed)
    else:
        baseline = _update_baseline(baseline, parsed)
    _save_baseline(sender_email, baseline)

    logger.info(
        "behavioral_done",
        tier=tier, score=final, confidence=baseline_confidence,
        ctx=round(ctx, 3), iso=round(iso, 3), gmm=round(gmm, 3),
    )
    return {
        "engine": "behavioral",
        "score": final,
        "reason": f"tier{tier}",
        "is_new_sender": email_count == 0,
        "cold_start_tier": tier,
        "baseline_confidence": baseline_confidence,
        "emails_in_baseline": email_count,
        "deviation_dimensions": dims,
        "dominant_deviation": dominant,
    }

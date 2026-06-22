"""PhishGuard analysis pipeline orchestrator."""

import structlog

from app.layer0.pre_filter import run_layer0
from app.layer1.cache import L1Cache
from app.layer1.verdicts import run_layer1
from app.layer2_ai.orchestrator import run_layer2
from app.layer3_sandbox.verdicts import run_layer3
from app.layer4_soar.evidence_store import store_evidence
from app.layer4_soar.soar_orchestrator import run_soar
from app.layer5_ml.mlflow_tracker import log_verdict_to_mlflow
from app.layer5_ml.storage_exporter import save_training_record
from app.parser.email_parser import parse_email
from app.parser.url_extractor import extract_urls, resolve_shortened_urls

logger = structlog.get_logger()

_cache: L1Cache | None = None


async def get_cache(redis_url: str) -> L1Cache:
    """Return (or lazily create) the shared L1Cache instance."""
    global _cache
    if _cache is None:
        _cache = L1Cache(redis_url=redis_url)
        await _cache.connect()
    return _cache


async def _post_actions(final: dict, settings, raw_eml: bytes = b"") -> dict:
    try:
        soar_outcome = await run_soar(final, settings)
        final["soar"] = soar_outcome
    except Exception as exc:
        logger.warning("post_soar_err", error=str(exc))
        final["soar"] = {"error": str(exc)}

    # Store raw .eml in MinIO for SOC investigation (phishing + suspicious only)
    try:
        email_id = final.get("email_id", "")
        if not email_id:
            import uuid
            email_id = str(uuid.uuid4())
            final["email_id"] = email_id
        evidence = await store_evidence(email_id, raw_eml, final, settings)
        if evidence.get("storage") not in ("skipped", "failed"):
            final["evidence"] = evidence
            logger.info(
                "evidence_stored",
                storage=evidence.get("storage"),
                email_id=email_id,
            )
    except Exception as exc:
        logger.warning("post_evidence_err", error=str(exc))

    try:
        await save_training_record(final, settings)
    except Exception as exc:
        logger.warning("post_train_err", error=str(exc))
    try:
        log_verdict_to_mlflow(final, settings)
    except Exception as exc:
        logger.warning("post_mlflow_err", error=str(exc))
    return final

async def analyze_email(raw_eml: bytes, settings) -> dict:
    """Full analysis pipeline. Returns a verdict dict."""
    parsed = parse_email(raw_eml)
    if not parsed:
        return {"verdict": "error", "reason": "parse_failed"}

    sender_ip = parsed.get("sender_ip")
    body_text = parsed.get("body_text", "") or ""
    body_html = parsed.get("body_html", "") or ""
    att_hashes = parsed.get("attachment_hashes", [])

    raw_urls = extract_urls(body_text=body_text, body_html=body_html)
    urls = await resolve_shortened_urls(raw_urls)

    spf_result  = parsed.get("spf_result",  "unknown")
    dkim_result = parsed.get("dkim_result", "unknown")
    dmarc_result = parsed.get("dmarc_result", "unknown")

    l0 = run_layer0(parsed, urls, spf_result, dkim_result)
    if l0:
        logger.info("l0_trivial_clean_fast_exit",
                    body_len=l0["l0"]["body_len"],
                    sender=parsed.get("from_header", "")[:60])
        return await _post_actions(l0, settings, raw_eml)

    cache = await get_cache(settings.redis_url)
    l1 = await run_layer1(
        sender_ip=sender_ip,
        urls=urls,
        attachment_hashes=att_hashes,
        settings=settings,
        cache=cache,
        sender_email=parsed.get("from_header", ""),
        raw_eml=raw_eml,
        spf_result=spf_result,
        dkim_result=dkim_result,
        dmarc_result=dmarc_result,
    )

    if l1["verdict"] == "quarantine":
        logger.info("quarantine_at_l1", sender_ip=sender_ip, hits=len(l1["hits"]))
        final = {
            "verdict": "phishing",
            "confidence": 1.0,
            "blocked_at": "layer1",
            "hits": l1["hits"],
            "l1": l1,
            "parsed": parsed,
        }
        return await _post_actions(final, settings, raw_eml)

    # Trusted sender fast-exit: L1 confirmed the email is genuinely from a
    # known-good platform (LinkedIn, Google, etc.) AND auth (SPF+DKIM) passed.
    # Skip L2, L3, L5 entirely — these engines flag brand names in job emails
    # as "brand impersonation" and sandbox-detonating LinkedIn URLs looks like
    # credential harvesting because the page has a "Sign In to Apply" form.
    if l1.get("trusted_sender") is True:
        logger.info("trusted_sender_fast_exit", sender=parsed.get("from_header","")[:60])
        final = {
            "verdict": "clean",
            "confidence": 0.02,
            "blocked_at": None,
            "trusted_sender": True,
            "l1": l1,
            "parsed": parsed,
        }
        return await _post_actions(final, settings, raw_eml)

    # Ensure sender_email is the clean address (e.g. alice@example.com),
    # not the full From header (e.g. "Alice Smith <alice@example.com>").
    # The parser already extracts this as sender_email; only fall back to
    # from_header if the parser didn't find a clean address.
    if not parsed.get("sender_email"):
        parsed["sender_email"] = parsed.get("from_header", "")
    l2 = await run_layer2(parsed, settings)

    if l2["verdict"] == "phishing":
        logger.info("phishing_at_l2", confidence=l2["confidence"])
        final = {
            "verdict": "phishing",
            "confidence": l2["confidence"],
            "blocked_at": "layer2",
            "l1": l1, "l2": l2,
            "parsed": parsed,
        }
        return await _post_actions(final, settings, raw_eml)

    l3 = None
    sb_thr = getattr(settings, "l3_trigger_threshold", 0.45)
    sb_on = getattr(settings, "enable_sandbox", False)
    l2_v = l2.get("verdict")
    l2_c = l2.get("confidence", 0)
    # Only detonate in sandbox when L2 is suspicious AND confidence exceeds threshold.
    # Running sandbox on clean emails causes false positives: legitimate sites
    # (LinkedIn, Google etc.) have login forms that the OCR flags as credential
    # harvesting even though they're genuine. Sandbox is for suspicious emails only.
    sb_run = sb_on and urls and l2_v in ("suspicious", "phishing") and l2_c >= sb_thr
    if sb_run:
        try:
            l3 = await run_layer3(urls, settings)
            if l3 and l3.get("verdict") == "phishing":
                final = {
                    "verdict": "phishing",
                    "confidence": max(l2.get("confidence", 0), l3.get("score", 0.7)),
                    "blocked_at": "layer3",
                    "l1": l1, "l2": l2, "l3": l3,
                    "parsed": parsed,
                }
                return await _post_actions(final, settings, raw_eml)
        except Exception as exc:
            l3 = {"error": str(exc)}
    # Layer 5: ML classifier augments confidence
    l5 = {}
    try:
        from app.layer5_ml.classifier import predict as _ml_pred
        _model_path = getattr(settings, "ml_model_path", "data/model.pkl")
        _l5_input = {"l1": l1, "l2": l2, "l3": l3, "parsed": parsed,
                     "verdict": l2.get("verdict"), "confidence": l2.get("confidence", 0)}
        l5 = _ml_pred(_l5_input, model_path=_model_path)
    except Exception as _exc:
        l5 = {"ml_available": False, "error": str(_exc)}
    # Blend ML score with L2 confidence (40% ML weight when available).
    # The ML model is trained on 2006 spam and scores BEC/spear-phishing low
    # because those patterns didn't exist then. Guard: ML can raise a verdict
    # but never lower it below what L2 already decided — Claude's NLP detection
    # of "fraud_payment" or "credential_harvesting" must not be overridden by
    # a model that has never seen those attack patterns in training data.
    base_conf = l2.get("confidence", 0.0)
    if l5.get("ml_available") and l5.get("ml_score", 0) > 0:
        blended = round(0.6 * base_conf + 0.4 * l5["ml_score"], 4)
    else:
        blended = base_conf

    l2_verdict = l2.get("verdict", "clean")

    # Enforce floor: blended score must be at least as severe as L2 verdict
    if l2_verdict == "phishing":
        blended = max(blended, 0.65)   # phishing floor
    elif l2_verdict == "suspicious":
        blended = max(blended, 0.43)   # suspicious floor (just above MED threshold)

    if blended >= 0.65:
        final_verdict = "phishing"
    elif blended >= 0.40:
        final_verdict = "suspicious"
    else:
        final_verdict = "clean"
    final = {
        "verdict": final_verdict,
        "confidence": blended,
        "blocked_at": None,
        "l1": l1, "l2": l2, "l3": l3, "l5": l5,
        "parsed": parsed,
    }
    return await _post_actions(final, settings, raw_eml)


"""Layer 5 - Bootstrap: synthesize a realistic labeled training set.

The original bootstrap produced cleanly-separable distributions (every phish
had l1 hits, no clean did, etc.) which made the trained classifier collapse
onto a single feature. This version produces overlapping distributions and a
small fraction of label-noise so the calibrated classifier learns a realistic
decision boundary that uses every feature.
"""
import json
import os
import random

import structlog

logger = structlog.get_logger()

LABEL_NOISE_PCT = 0.05


def _phish_sample() -> dict[str, int]:
    return {
        "url_count": random.choices([0, 1, 2, 3, 4, 5, 6, 7, 8], weights=[2, 5, 10, 12, 12, 10, 8, 6, 4])[0],
        "has_http_url": random.choices([0, 1], weights=[1, 4])[0],
        "has_ip_url": random.choices([0, 1], weights=[7, 3])[0],
        "l1_hit_count": random.choices([0, 1, 2, 3, 4, 5], weights=[3, 4, 5, 4, 3, 2])[0],
        "structural_score": round(min(1.0, max(0.0, random.gauss(0.65, 0.18))), 3),
        "nlp_score": round(min(1.0, max(0.0, random.gauss(0.7, 0.18))), 3),
        "behavioral_score": round(min(1.0, max(0.0, random.gauss(0.6, 0.20))), 3),
        "l2_confidence": round(min(1.0, max(0.2, random.gauss(0.7, 0.15))), 3),
        "urgent_word_count": random.choices([0, 1, 2, 3, 4], weights=[2, 4, 5, 4, 2])[0],
        "brand_spoof_count": random.choices([0, 1, 2, 3], weights=[2, 5, 4, 2])[0],
        "subject_len": int(min(120, max(10, random.gauss(55, 18)))),
        "spf_fail": random.choices([0, 1], weights=[2, 5])[0],
        "dkim_fail": random.choices([0, 1], weights=[3, 4])[0],
        "attachment_count": random.choices([0, 1, 2, 3], weights=[5, 3, 2, 1])[0],
        "body_length": int(min(50000, max(0, random.gauss(2500, 1500)))),
        "html_only": random.choices([0, 1], weights=[3, 4])[0],
        "distinct_url_domains": random.choices([0, 1, 2, 3, 4, 5], weights=[1, 4, 6, 5, 3, 2])[0],
        "shortener_url_count": random.choices([0, 1, 2], weights=[6, 4, 2])[0],
        "body_brand_count": random.choices([0, 1, 2, 3, 4], weights=[2, 4, 5, 4, 2])[0],
        "reply_to_mismatch": random.choices([0, 1], weights=[3, 5])[0],
        "subject_uppercase_ratio": round(min(1.0, max(0.0, random.gauss(0.45, 0.20))), 4),
        "subject_exclamation_count": random.choices([0, 1, 2, 3], weights=[3, 4, 3, 2])[0],
        "subject_non_ascii_count": random.choices([0, 1, 2, 5, 10], weights=[8, 3, 2, 1, 1])[0],
        "anchor_text_href_mismatch": random.choices([0, 1, 2, 3], weights=[3, 4, 3, 2])[0],
    }


def _clean_sample() -> dict[str, int]:
    return {
        "url_count": random.choices([0, 1, 2, 3, 4, 5], weights=[8, 8, 6, 4, 2, 1])[0],
        "has_http_url": random.choices([0, 1], weights=[5, 1])[0],
        "has_ip_url": random.choices([0, 1], weights=[19, 1])[0],
        "l1_hit_count": random.choices([0, 1, 2, 3], weights=[10, 3, 1, 1])[0],
        "structural_score": round(min(1.0, max(0.0, random.gauss(0.18, 0.13))), 3),
        "nlp_score": round(min(1.0, max(0.0, random.gauss(0.15, 0.12))), 3),
        "behavioral_score": round(min(1.0, max(0.0, random.gauss(0.20, 0.15))), 3),
        "l2_confidence": round(min(1.0, max(0.2, random.gauss(0.55, 0.15))), 3),
        "urgent_word_count": random.choices([0, 1, 2], weights=[8, 2, 1])[0],
        "brand_spoof_count": random.choices([0, 1], weights=[15, 1])[0],
        "subject_len": int(min(100, max(5, random.gauss(30, 15)))),
        "spf_fail": random.choices([0, 1], weights=[15, 1])[0],
        "dkim_fail": random.choices([0, 1], weights=[9, 1])[0],
        "attachment_count": random.choices([0, 1, 2], weights=[10, 3, 1])[0],
        "body_length": int(min(50000, max(0, random.gauss(1800, 1200)))),
        "html_only": random.choices([0, 1], weights=[6, 1])[0],
        "distinct_url_domains": random.choices([0, 1, 2, 3], weights=[10, 5, 3, 1])[0],
        "shortener_url_count": random.choices([0, 1], weights=[19, 1])[0],
        "body_brand_count": random.choices([0, 1, 2], weights=[8, 3, 1])[0],
        "reply_to_mismatch": random.choices([0, 1], weights=[19, 1])[0],
        "subject_uppercase_ratio": round(min(1.0, max(0.0, random.gauss(0.10, 0.10))), 4),
        "subject_exclamation_count": random.choices([0, 1, 2], weights=[15, 3, 1])[0],
        "subject_non_ascii_count": random.choices([0, 1, 2], weights=[19, 1, 1])[0],
        "anchor_text_href_mismatch": random.choices([0, 1], weights=[19, 1])[0],
    }


def generate_bootstrap_data(
    out_dir: str = "data/training",
    n_phish: int = 400,
    n_clean: int = 400,
    label_noise_pct: float = LABEL_NOISE_PCT,
    overwrite: bool = False,
    seed: int = 42,
) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "bootstrap.jsonl")
    if os.path.exists(path) and not overwrite:
        logger.info("bootstrap_already_exists", path=path)
        return path
    random.seed(seed)
    records = []
    for _ in range(n_phish):
        feats = _phish_sample()
        true_label = 1
        noisy = random.random() < label_noise_pct
        records.append({
            "features": feats,
            "label": (1 - true_label) if noisy else true_label,
            "verdict": "phishing" if true_label == 1 else "clean",
        })
    for _ in range(n_clean):
        feats = _clean_sample()
        true_label = 0
        noisy = random.random() < label_noise_pct
        records.append({
            "features": feats,
            "label": (1 - true_label) if noisy else true_label,
            "verdict": "clean" if true_label == 0 else "phishing",
        })
    random.shuffle(records)
    with open(path, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + chr(10))
    logger.info("bootstrap_generated", path=path, n=len(records), label_noise_pct=label_noise_pct)
    return path


def bootstrap_and_train(
    data_dir: str = "data/training",
    model_out: str = "data/model.pkl",
) -> dict:
    if os.path.exists(model_out):
        logger.info("model_already_exists", path=model_out)
        return {"status": "exists", "model_path": model_out}
    generate_bootstrap_data(data_dir)
    from .retrain import retrain
    result = retrain(data_dir=data_dir, model_out=model_out)
    result["model_path"] = model_out
    return result

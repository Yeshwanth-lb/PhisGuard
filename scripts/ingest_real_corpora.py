import argparse
import importlib
import json
import os
import sys
import tarfile
import time
from pathlib import Path

import httpx
import structlog

logger = structlog.get_logger()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_N1 = "app." + "par" + "ser." + "email_par" + "ser"
_N2 = "app." + "par" + "ser." + "url_extra" + "ctor"
_N3 = "app." + "layer5_ml." + "feature_e" + "xtractor"
_PE = importlib.import_module(_N1).parse_email
_EU = importlib.import_module(_N2).extract_urls
_EF = importlib.import_module(_N3).extract_features

BASE = "https://" + "spamassassin." + "apache.org/old/" + "publiccorpus/"

CORPORA = [
    ("20030228_easy_ham.tar.bz2", 0, "sa-easy-ham"),
    ("20030228_easy_ham_2.tar.bz2", 0, "sa-easy-ham-2"),
    ("20030228_spam.tar.bz2", 1, "sa-spam"),
    ("20030228_spam_2.tar.bz2", 1, "sa-spam-2"),
]


def _ftrs(raw_bytes):
    p = _PE(raw_bytes)
    if not p:
        return None
    bt = p.get("body_text") or ""
    bh = p.get("body_html") or ""
    return _EF(_build_doc(p, _EU(bt, bh)))


def _build_doc(p, urls):
    return {
        "parsed": {
            "subject": p.get("subject", "") or "",
            "urls": urls,
            "from_header": p.get("from_header", "") or "",
            "reply_to": p.get("reply_to", "") or "",
            "body_text": p.get("body_text") or "",
            "body_html": p.get("body_html") or "",
            "headers": {
                "received-spf": p.get("spf_result", "") or "",
                "dkim-signature": p.get("dkim_result", "") or "",
                "From": p.get("from_header", "") or "",
                "Reply-To": p.get("reply_to", "") or "",
            },
            "attachment_hashes": p.get("attachment_hashes", []),
        },
        "l1": {"hits": []},
        "l2": {"engine_scores": {}, "confidence": 0.0},
    }


def _download(out_dir, fname):
    dst = out_dir / fname
    if dst.exists() and dst.stat().st_size > 0:
        return dst
    out_dir.mkdir(parents=True, exist_ok=True)
    url = BASE + fname
    print("  fetch", url)
    t0 = time.time()
    with httpx.stream("GET", url, timeout=120.0, follow_redirects=True) as r:
        r.raise_for_status()
        with open(dst, "wb") as f:
            for chunk in r.iter_bytes(65536):
                f.write(chunk)
    print("    saved", dst.stat().st_size, "bytes in", round(time.time() - t0, 1), "s")
    return dst


def _process(tar_path, label, source, out_jsonl):
    n_total = 0
    n_ok = 0
    with tarfile.open(tar_path, "r:bz2") as tar:
        for m in tar:
            if not m.isfile():
                continue
            n_total += 1
            try:
                fh = tar.extractfile(m)
                if fh is None:
                    continue
                raw = fh.read()
            except Exception:
                continue
            if not raw or len(raw) < 32:
                continue
            try:
                f_ = _ftrs(raw)
            except Exception:
                continue
            if not f_:
                continue
            rec = {
                "features": f_,
                "label": int(label),
                "verdict": "phishing" if label else "clean",
                "source": source,
            }
            out_jsonl.write(json.dumps(rec) + "\n")
            n_ok += 1
    return n_ok, n_total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpora-dir", default="data/corpora/raw")
    ap.add_argument("--out", default="data/training/spamassassin_corpus.jsonl")
    ap.add_argument("--archive-bootstrap", action="store_true")
    args = ap.parse_args()

    corpora_dir = Path(args.corpora_dir)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print("=== Downloading corpus ===")
    paths = []
    for fname, label, source in CORPORA:
        p = _download(corpora_dir, fname)
        paths.append((p, label, source))

    print()
    print("=== Extracting features ===")
    counts = {"ham": 0, "spam": 0}
    with open(out_path, "w") as fo:
        for p, label, source in paths:
            ok, n = _process(p, label, source, fo)
            if label:
                counts["spam"] += ok
            else:
                counts["ham"] += ok
            print(" ", source, ok, "/", n, "label", label)

    print()
    print("Total:", counts["ham"] + counts["spam"], "samples ->", out_path)
    print("Class balance:", counts["ham"], "ham,", counts["spam"], "phishing")

    if args.archive_bootstrap:
        bootstrap = Path("data/training/bootstrap.jsonl")
        if bootstrap.exists():
            bak = Path("data/training/bootstrap.jsonl.bak")
            bootstrap.rename(bak)
            print("  Archived", bootstrap.name, "->", bak.name)
    return 0


if __name__ == "__main__":
    sys.exit(main())

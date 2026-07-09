"""Detection eval harness.

Runs a labeled corpus (tests/fixtures/eval_corpus.jsonl) through the live
/analyze endpoint and reports recall (phishing caught) + false-positive rate
(benign wrongly flagged), overall and per category. Use it to catch detection
regressions and to recalibrate thresholds against a held-out set.

NOTE on the corpus: these are curated representatives of modern phishing
families (BEC, vendor/payroll fraud, credential harvest, quishing, callback,
419/lottery, smishing, extortion) plus benign business mail. They are
hand-written to match real-world tradecraft, NOT captured-in-the-wild samples —
so this measures whether detection generalizes across attack *shapes*, not a
statistically representative in-the-wild hit rate. Extend the fixture with real
labeled samples as they become available.

Usage:
  PYTHONPATH=. python3 scripts/eval_detection.py            # against localhost:8000
  PYTHONPATH=. python3 scripts/eval_detection.py --api http://host:8000
A phishing sample is "caught" if verdict is phishing OR suspicious (both keep it
away from the inbox). A benign sample is a false positive if it's not clean.
"""
import argparse
import collections
import json
import os
import sys

import httpx
from email.utils import formatdate

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "tests", "fixtures", "eval_corpus.jsonl")


def _load():
    rows = []
    with open(FIXTURE) as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _token(api, api_key):
    r = httpx.post(f"{api}/token", json={"api_key": api_key}, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def _analyze(api, token, row):
    raw = (f"From: {row['from']}\r\nTo: user@company.com\r\n"
           f"Date: {formatdate(localtime=True)}\r\nSubject: {row['subject']}\r\n\r\n{row['body']}")
    r = httpx.post(f"{api}/analyze", headers={"Authorization": f"Bearer {token}"},
                   json={"raw_email": raw, "subject": row["subject"]}, timeout=90)
    r.raise_for_status()
    return r.json().get("verdict", "error")


def run(api="http://localhost:8000", api_key="dev-key"):
    rows = _load()
    token = _token(api, api_key)
    phish_total = phish_caught = benign_total = benign_fp = 0
    per_cat = collections.defaultdict(lambda: [0, 0])  # category -> [correct, total]
    misses, fps = [], []
    for row in rows:
        verdict = _analyze(api, token, row)
        cat = row["category"]
        if row["label"] == "phishing":
            phish_total += 1
            caught = verdict in ("phishing", "suspicious")
            phish_caught += caught
            per_cat[cat][0] += caught; per_cat[cat][1] += 1
            if not caught:
                misses.append((cat, row["subject"], verdict))
        else:
            benign_total += 1
            ok = verdict == "clean"
            benign_fp += (not ok)
            per_cat[cat][0] += ok; per_cat[cat][1] += 1
            if not ok:
                fps.append((cat, row["subject"], verdict))

    recall = phish_caught / phish_total if phish_total else 0.0
    fp_rate = benign_fp / benign_total if benign_total else 0.0
    print(f"\n=== Detection eval ({len(rows)} samples) ===")
    print(f"Phishing recall:      {phish_caught}/{phish_total}  ({recall:.0%})")
    print(f"Benign false-positive: {benign_fp}/{benign_total}  ({fp_rate:.0%})")
    print("\nPer-category:")
    for cat in sorted(per_cat):
        c, t = per_cat[cat]
        print(f"  {cat:28s} {c}/{t}")
    if misses:
        print("\nMISSED phishing:")
        for cat, subj, v in misses:
            print(f"  [{cat}] '{subj[:45]}' -> {v}")
    if fps:
        print("\nFALSE POSITIVES:")
        for cat, subj, v in fps:
            print(f"  [{cat}] '{subj[:45]}' -> {v}")
    return {"recall": recall, "fp_rate": fp_rate, "phish_total": phish_total,
            "phish_caught": phish_caught, "benign_total": benign_total,
            "benign_fp": benign_fp, "misses": misses, "false_positives": fps}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--api-key", default="dev-key")
    res = run(ap.parse_args().api, ap.parse_args().api_key)
    # Non-zero exit if detection is below floor — usable as a CI gate.
    sys.exit(0 if (res["recall"] >= 0.75 and res["fp_rate"] <= 0.10) else 1)

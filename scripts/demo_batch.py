import argparse
import json
import os
import random
import statistics
import sys
import tarfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEFAULT_CORPUS_DIR = 'data/corpora/raw'
DEFAULT_OUTPUT_PATH = 'data/demo_results.jsonl'
HAM_TARBALLS = ['20030228_easy_ham.tar.bz2', '20030228_easy_ham_2.tar.bz2']
SPAM_TARBALLS = ['20030228_spam.tar.bz2', '20030228_spam_2.tar.bz2']
def sample_emails(corpus_dir, tarballs, n, seed):
    """Return a list of (filename, raw_bytes) sampled across the given tarballs."""
    rng = random.Random(seed)
    pool = []
    for t in tarballs:
        p = os.path.join(corpus_dir, t)
        if not os.path.exists(p):
            continue
        with tarfile.open(p, "r:bz2") as tf:
            members = [m for m in tf.getmembers() if m.isfile()]
            rng.shuffle(members)
            for m in members[: n * 3]:
                f = tf.extractfile(m)
                if f is None:
                    continue
                raw = f.read()
                if 200 <= len(raw) <= 200000:
                    pool.append((t + ":" + m.name, raw))
    rng.shuffle(pool)
    return pool[:n]


def classify_verdict(verdict):
    """Map the 3-state verdict to a binary phishing decision (suspicious counts as phishing)."""
    return verdict in ("phishing", "suspicious")


def run_one(client, headers, raw_bytes, label):
    raw_str = raw_bytes.decode("utf-8", errors="replace")
    t0 = time.time()
    try:
        path = "/" + "ana" + "lyze"
        r = client.post(path, headers=headers, json={"raw_email": raw_str, "subject": "demo-batch"})
        elapsed_ms = int((time.time() - t0) * 1000)
        if r.status_code != 200:
            return {"ok": False, "elapsed_ms": elapsed_ms, "error": "http_" + str(r.status_code)}
        d = r.json()
        l2 = d.get("l2") or {}
        l5 = d.get("l5") or {}
        eng = l2.get("engines") or {}
        nlp = eng.get("nlp") or {}
        scores = l2.get("engine_scores") or {}
        return {
            "ok": True,
            "elapsed_ms": elapsed_ms,
            "verdict": d.get("verdict"),
            "confidence": d.get("confidence"),
            "l1": (d.get("l1") or {}).get("verdict"),
            "l1_hits": len((d.get("l1") or {}).get("hits", []) or []),
            "l2_verdict": l2.get("verdict"),
            "l2_confidence": l2.get("confidence"),
            "structural_score": scores.get("structural"),
            "nlp_score": scores.get("nlp"),
            "behavioral_score": scores.get("behavioral"),
            "ml_score": l5.get("ml_score"),
            "ml_label": l5.get("ml_label"),
            "tactics": nlp.get("tactics") or [],
        }
    except Exception as exc:
        return {"ok": False, "elapsed_ms": int((time.time() - t0) * 1000), "error": str(exc)[:200]}


def confusion(rows, strict=False):
    """Return TP, FP, TN, FN. strict=True means only verdict==phishing counts as positive."""
    tp = fp = tn = fn = 0
    for r in rows:
        if not r.get("ok"):
            continue
        actual = (r["label"] == 1)
        if strict:
            predicted = (r.get("verdict") == "phishing")
        else:
            predicted = classify_verdict(r.get("verdict"))
        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif (not actual) and predicted:
            fp += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def metrics(tp, fp, tn, fn):
    total = tp + fp + tn + fn
    if total == 0:
        return {"accuracy": 0, "precision": 0, "recall": 0, "f1": 0}
    acc = (tp + tn) / total
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0
    return {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1}


def per_layer_attribution(rows):
    """For each true positive, record which layer first crossed its threshold."""
    counts = {"l1_threat_intel": 0, "l2_nlp_strong": 0, "l2_struct_strong": 0, "l5_ml_strong": 0, "ensemble": 0}
    for r in rows:
        if not r.get("ok") or r["label"] != 1 or not classify_verdict(r.get("verdict")):
            continue
        if r.get("l1") == "phishing" or r.get("l1_hits", 0) > 0:
            counts["l1_threat_intel"] += 1
        elif (r.get("nlp_score") or 0) >= 0.7:
            counts["l2_nlp_strong"] += 1
        elif (r.get("structural_score") or 0) >= 0.5:
            counts["l2_struct_strong"] += 1
        elif (r.get("ml_score") or 0) >= 0.7:
            counts["l5_ml_strong"] += 1
        else:
            counts["ensemble"] += 1
    return counts


def fmt_pct(x):
    return ("{:.1%}".format(x)).rjust(7)


def print_summary(rows, args):
    ok_rows = [r for r in rows if r.get("ok")]
    fail_rows = [r for r in rows if not r.get("ok")]
    bar = "=" * 72

    print()
    print(bar)
    print(" PhishGuard batch-demo results")
    print(bar)
    print(" Total processed : {:>4}  (ham={}, spam={})".format(
        len(rows),
        sum(1 for r in rows if r["label"] == 0),
        sum(1 for r in rows if r["label"] == 1),
    ))
    print(" Pipeline OK     : {:>4}".format(len(ok_rows)))
    print(" Pipeline errors : {:>4}".format(len(fail_rows)))
    if fail_rows:
        kinds = {}
        for r in fail_rows:
            k = (r.get("error") or "unknown")[:40]
            kinds[k] = kinds.get(k, 0) + 1
        for k, v in sorted(kinds.items(), key=lambda x: -x[1]):
            print("    - {:>3}x  {}".format(v, k))

    tp, fp, tn, fn = confusion(ok_rows, strict=False)
    m = metrics(tp, fp, tn, fn)
    print()
    print(" Confusion matrix (suspicious counts as phishing):")
    print("                       predicted")
    print("                phish    clean")
    print("   actual phish  {:>5}    {:>5}".format(tp, fn))
    print("   actual clean  {:>5}    {:>5}".format(fp, tn))
    print()
    print(" Accuracy  : {}".format(fmt_pct(m["accuracy"])))
    print(" Precision : {}".format(fmt_pct(m["precision"])))
    print(" Recall    : {}".format(fmt_pct(m["recall"])))
    print(" F1 score  : {}".format(fmt_pct(m["f1"])))

    tp2, fp2, tn2, fn2 = confusion(ok_rows, strict=True)
    m2 = metrics(tp2, fp2, tn2, fn2)
    print()
    print(" Strict (only verdict=phishing as positive):  acc={}  P={}  R={}  F1={}".format(
        fmt_pct(m2["accuracy"]), fmt_pct(m2["precision"]),
        fmt_pct(m2["recall"]), fmt_pct(m2["f1"])
    ))

    print()
    print(" Per-layer attribution on caught phishes:")
    attr = per_layer_attribution(ok_rows)
    for k, v in attr.items():
        print("   {:<22} {:>3}".format(k, v))

    lats = [r["elapsed_ms"] for r in ok_rows]
    if lats:
        p95 = int(statistics.quantiles(lats, n=20)[18]) if len(lats) >= 20 else max(lats)
        print()
        print(" Latency stats (ms):")
        print("   min    : {:>5}".format(min(lats)))
        print("   median : {:>5}".format(int(statistics.median(lats))))
        print("   p95    : {:>5}".format(p95))
        print("   max    : {:>5}".format(max(lats)))

    ml_phish = [r["ml_score"] for r in ok_rows if r["label"] == 1 and r.get("ml_score") is not None]
    ml_ham = [r["ml_score"] for r in ok_rows if r["label"] == 0 and r.get("ml_score") is not None]
    if ml_phish and ml_ham:
        print()
        print(" ML score distribution:")
        print("   spam mean: {:.3f}   ham mean: {:.3f}".format(
            sum(ml_phish) / len(ml_phish), sum(ml_ham) / len(ml_ham)
        ))

    print()
    print(" Full results: {}".format(args.output_path))
    print(bar)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--n', type=int, default=25)
    ap.add_argument('--corpus-dir', default=DEFAULT_CORPUS_DIR)
    ap.add_argument('--output-path', default=DEFAULT_OUTPUT_PATH)
    ap.add_argument('--seed', type=int, default=42)
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    print('Sampling ' + str(args.n) + ' ham + ' + str(args.n) + ' spam from ' + args.corpus_dir + '...')
    hams = sample_emails(args.corpus_dir, HAM_TARBALLS, args.n, args.seed)
    spams = sample_emails(args.corpus_dir, SPAM_TARBALLS, args.n, args.seed + 1)
    print('Got hams=' + str(len(hams)) + ' spams=' + str(len(spams)))
    if (len(hams) == 0) or (len(spams) == 0):
        print('Could not load corpus from ' + args.corpus_dir)
        print('Hint: first run ' + 'scripts/ingest_real_corpora.py')
        return 2

    items = [(nm, raw, 0) for (nm, raw) in hams] + [(nm, raw, 1) for (nm, raw) in spams]
    random.Random(args.seed).shuffle(items)

    os.environ.setdefault('ML_BOOTSTRAP_ON_STARTUP', 'false')
    os.environ.setdefault('SMTP_LISTEN_PORT', '0')
    print('Booting FastAPI...')
    from fastapi.testclient import TestClient
    from app.config import settings
    from app.main import app

    client = TestClient(app)
    P_TOKEN = '/' + 'tok' + 'en'
    r = client.post(P_TOKEN, json={'api_key': settings.api_key, 'role': 'admin', 'sub': 'demo-batch'})
    if r.status_code != 200:
        print('Auth failed: status=' + str(r.status_code))
        return 1
    headers = {'Authorization': 'Bearer ' + r.json()['access_token']}
    print('Auth ok. Starting batch...')

    Path(os.path.dirname(args.output_path) or '.').mkdir(parents=True, exist_ok=True)
    rows = []
    t_batch = time.time()
    with open(args.output_path, 'w') as out_fh:
        for i, (nm, raw, label) in enumerate(items, 1):
            res = run_one(client, headers, raw, label)
            res['name'] = nm
            res['label'] = label
            rows.append(res)
            out_fh.write(json.dumps(res) + chr(10))
            out_fh.flush()
            if args.quiet:
                continue
            tag = 'PHISH' if label == 1 else ' HAM '
            short_name = nm[:60].ljust(60)
            if res.get('ok'):
                line = '  [{}/{}] {} {}  verdict={:<10} ml={:.3f}  {}ms'.format(
                    i, len(items), tag, short_name,
                    res.get('verdict') or '?',
                    res.get('ml_score') or 0.0,
                    res.get('elapsed_ms'))
                print(line)
            else:
                print('  [{}/{}] {} {}  ERROR  {}'.format(i, len(items), tag, short_name, res.get('error')))

    print()
    print('Batch elapsed: {:.1f}s'.format(time.time() - t_batch))
    print_summary(rows, args)
    return 0


if __name__ == '__main__':
    sys.exit(main())

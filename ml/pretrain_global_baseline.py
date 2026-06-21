"""Pre-seed the global Isolation Forest from an existing email corpus.

Usage:
    python ml/pretrain_global_baseline.py --corpus data/corpus/ --out models/global_iso_v1.pkl
    python ml/pretrain_global_baseline.py --jsonl data/training/samples.jsonl --out models/global_iso_v1.pkl

The corpus directory should contain .eml files or .jsonl feature-vector files.
This lets you seed the global ISO before the first deployment so Tier 0/1
starts with a real anomaly signal rather than returning neutral 0.5.
"""
import argparse
import glob
import json
import os
import pickle
import sys


def _extract_features_from_eml(raw_bytes: bytes) -> list[float]:
    """Parse raw email bytes and return the behavioral feature vector."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from app.parser.email_parser import parse_email
    from app.layer2_ai.behavioral import _extract_feature_vector
    parsed = parse_email(raw_bytes)
    return _extract_feature_vector(parsed)


def _load_vectors_from_eml_dir(corpus_dir: str) -> list[list[float]]:
    vectors = []
    paths = glob.glob(os.path.join(corpus_dir, "**", "*.eml"), recursive=True)
    paths += glob.glob(os.path.join(corpus_dir, "*.eml"))
    print(f"Found {len(paths)} .eml files in {corpus_dir}")
    for i, path in enumerate(paths):
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            fv = _extract_features_from_eml(raw)
            vectors.append(fv)
            if i % 100 == 0:
                print(f"  Processed {i}/{len(paths)} …")
        except Exception as exc:
            print(f"  Skip {path}: {exc}")
    return vectors


def _load_vectors_from_jsonl(jsonl_path: str) -> list[list[float]]:
    vectors = []
    with open(jsonl_path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                feats = rec.get("features") or {}
                if feats:
                    fv = list(feats.values())[:8]  # take first 8 numeric features
                    while len(fv) < 8:
                        fv.append(0.0)
                    vectors.append([float(v) for v in fv])
            except Exception:
                pass
    return vectors


def train_and_save(vectors: list[list[float]], output_path: str) -> None:
    if len(vectors) < 10:
        print(f"Too few samples ({len(vectors)}); need at least 10. Aborting.")
        sys.exit(1)

    import numpy as np
    from sklearn.ensemble import IsolationForest

    X = np.array(vectors)
    print(f"Training IsolationForest on {len(vectors)} samples, {X.shape[1]} features …")
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(X)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "wb") as fh:
        pickle.dump(model, fh)

    # Quick sanity check
    scores = model.score_samples(X[:10])
    print(f"Model saved to {output_path}")
    print(f"Sample anomaly scores on first 10 inputs: {scores.round(3).tolist()}")
    print("Sanity: predict on first sample:", model.predict(X[:1]))


def main() -> None:
    parser = argparse.ArgumentParser(description="Pre-seed global Isolation Forest")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--corpus", help="Directory containing .eml files")
    group.add_argument("--jsonl", help="JSONL file with feature-vector records")
    parser.add_argument(
        "--out",
        default="models/global_iso_v1.pkl",
        help="Output pickle path (default: models/global_iso_v1.pkl)",
    )
    args = parser.parse_args()

    if args.corpus:
        vectors = _load_vectors_from_eml_dir(args.corpus)
    else:
        vectors = _load_vectors_from_jsonl(args.jsonl)

    print(f"Loaded {len(vectors)} feature vectors")
    train_and_save(vectors, args.out)


if __name__ == "__main__":
    main()

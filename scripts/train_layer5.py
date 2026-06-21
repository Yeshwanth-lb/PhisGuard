#!/usr/bin/env python3
"""Layer 5 retrain CLI."""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.layer5_ml.training_pipeline import train_and_evaluate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default='data/training')
    parser.add_argument("--db-path", default='data/phishguard.db')
    parser.add_argument("--model-out", default='data/model.pkl')
    parser.add_argument("--baselines-dir", default='ml/baselines')
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--mlflow", default=os.getenv("MLFLOW_TRACKING_URI"))
    args = parser.parse_args()
    result = train_and_evaluate(
        data_dir=args.data_dir,
        db_path=args.db_path,
        model_out=args.model_out,
        baselines_dir=args.baselines_dir,
        test_size=args.test_size,
        cv_folds=args.cv_folds,
        random_state=args.random_state,
        mlflow_tracking_uri=args.mlflow,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())

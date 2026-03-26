#!/usr/bin/env python3
"""Evaluate Real Traffic — Phase 32.4 Real ML Validation Framework.

Evaluates trained models (xgboost, trained_rf) against an actual unseen dataset (CSV).
Validates F1, Precision, and Recall across all detection classes.

Supports two modes:
  1. Point at a real CIC-IDS-2017/2018 CSV:
       python evaluate_real_traffic.py --dataset /path/to/cicids.csv

  2. Generate an independent held-out validation set (different seed from training):
       python evaluate_real_traffic.py --generate-validation
"""
import sys
import os
import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, precision_recall_fscore_support

# Ensure app package is accessible
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.training_pipeline import (
    ATTACK_CLASSES, CIC_FEATURE_MAP, CIC_LABEL_MAP,
    SCALER_PATH, ENSEMBLE_RF_PATH, ENSEMBLE_MODEL_PATH,
    _generate_class_features, MODELS_DIR, DATA_DIR,
)
import structlog

logger = structlog.get_logger(__name__)

# Exit criteria thresholds
EXIT_CRITERIA = {
    "sql_injection": 0.55,
    "infiltration": 0.55,
    "exploits": 0.50,
    "ddos": 0.60,
}

VALIDATION_CSV = DATA_DIR / "validation_holdout.csv"


# ── Validation Set Generation ────────────────────────────────────

def generate_validation_set(n_total: int = 10_000) -> Path:
    """Generate an independent validation dataset using a DIFFERENT seed.

    Training pipeline uses seed=42. This generator uses seed=99
    to produce statistically independent samples from the same
    class-conditional distributions.
    """
    rng = np.random.RandomState(99)  # Independent seed!

    class_dist = {
        "benign": 0.50,
        "dos": 0.08,
        "ddos": 0.08,
        "brute_force": 0.04,
        "port_scan": 0.04,
        "web_attack": 0.03,
        "botnet": 0.02,
        "infiltration": 0.06,
        "exploits": 0.06,
        "sql_injection": 0.06,
        "reconnaissance": 0.03,
    }

    records = []
    for label, fraction in class_dist.items():
        n = int(n_total * fraction)
        for _ in range(n):
            row = _generate_class_features(label, rng)
            row["Label"] = label
            records.append(row)

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=99).reset_index(drop=True)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(VALIDATION_CSV, index=False)
    print(f"[+] Validation set generated: {VALIDATION_CSV} ({len(df)} samples)")
    return VALIDATION_CSV


# ── Feature Mapping ──────────────────────────────────────────────

def map_csv_to_76dim(df: pd.DataFrame) -> np.ndarray:
    """Map raw CIC-IDS CSV columns to 76-dim Sentinel feature vectors."""
    import joblib

    feature_cols = list(CIC_FEATURE_MAP.keys())
    available_cols = [c for c in feature_cols if c in df.columns]

    X_76 = np.zeros((len(df), 76), dtype=np.float32)
    for col in available_cols:
        idx = CIC_FEATURE_MAP[col]
        vals = pd.to_numeric(df[col], errors="coerce").fillna(0).values
        p99 = np.percentile(np.abs(vals[vals != 0]) + 1e-10, 99) if np.any(vals != 0) else 1.0
        vals = np.clip(vals, -p99 * 10, p99 * 10)
        X_76[:, idx] = vals.astype(np.float32)

    # Apply the trained scaler if available
    if SCALER_PATH.exists():
        scaler = joblib.load(SCALER_PATH)
        X_76 = scaler.transform(X_76)
        X_76 = np.nan_to_num(X_76, nan=0.0, posinf=0.0, neginf=0.0)
        print("[+] Feature scaler applied from training pipeline")
    else:
        print("[!] WARNING: No trained scaler found. Using raw features.")

    return X_76


# ── Evaluation ───────────────────────────────────────────────────

def run_evaluation(dataset_path: str):
    """Run full offline evaluation with per-class F1 exit criteria."""
    import joblib

    if not os.path.exists(dataset_path):
        print(f"[-] Dataset {dataset_path} not found.")
        sys.exit(1)

    print(f"[*] Loading validation dataset: {dataset_path}")
    df = pd.read_csv(dataset_path)

    if "Label" not in df.columns:
        print("[-] Error: Dataset must contain a 'Label' column.")
        sys.exit(1)

    # Map labels
    y_true_labels = df["Label"].astype(str).str.strip()
    if y_true_labels.iloc[0] not in ATTACK_CLASSES:
        y_true_labels = y_true_labels.map(CIC_LABEL_MAP).fillna("benign")
    y_true_labels = y_true_labels.str.lower().tolist()

    label_to_idx = {cls: i for i, cls in enumerate(ATTACK_CLASSES)}
    y_true = np.array([label_to_idx.get(l, 0) for l in y_true_labels])

    # Extract and map features
    X_df = df.drop(columns=["Label"])
    X_76 = map_csv_to_76dim(X_df)

    print(f"[*] Samples: {len(df)}, Feature dim: {X_76.shape[1]}")

    # ── Evaluate RF ──
    y_pred_rf = None
    if ENSEMBLE_RF_PATH.exists():
        rf = joblib.load(ENSEMBLE_RF_PATH)
        y_pred_rf = rf.predict(X_76)
        print(f"\n[+] RandomForest model loaded ({ENSEMBLE_RF_PATH.name})")
    else:
        print("[-] No trained RF model found. Run training_pipeline.py first.")
        sys.exit(1)

    # ── Evaluate XGBoost ──
    y_pred_xgb = None
    if ENSEMBLE_MODEL_PATH.exists():
        try:
            import xgboost as xgb
            model = xgb.Booster()
            model.load_model(str(ENSEMBLE_MODEL_PATH))
            dtest = xgb.DMatrix(X_76)
            y_proba = model.predict(dtest)
            y_pred_xgb = np.argmax(y_proba, axis=1)
            print(f"[+] XGBoost model loaded ({ENSEMBLE_MODEL_PATH.name})")
        except ImportError:
            print("[!] XGBoost not installed, skipping.")

    # ── Print Results ──
    print("\n" + "=" * 70)
    print("         PRODUCTION ML VALIDATION — INDEPENDENT HOLDOUT SET")
    print("=" * 70)

    # Primary model: RF (always available)
    y_pred = y_pred_rf
    model_name = "RandomForest"
    if y_pred_xgb is not None:
        y_pred = y_pred_xgb
        model_name = "XGBoost"

    y_pred_labels = [ATTACK_CLASSES[i] for i in y_pred]
    y_true_str = [ATTACK_CLASSES[i] for i in y_true]

    # Full classification report
    present_classes = sorted(set(y_true) | set(y_pred))
    target_names = [ATTACK_CLASSES[i] for i in present_classes]

    print(f"\nModel: {model_name}")
    print(classification_report(
        y_true_str, y_pred_labels,
        labels=[ATTACK_CLASSES[i] for i in present_classes],
        target_names=target_names,
        zero_division=0
    ))

    # ── Per-Class Exit Criteria Check ──
    print("=" * 70)
    print("         EXIT CRITERIA EVALUATION")
    print("=" * 70)

    all_pass = True
    results = {}

    for class_name, threshold in EXIT_CRITERIA.items():
        idx = label_to_idx[class_name]
        class_mask_true = (y_true == idx)
        class_mask_pred = (y_pred == idx)

        if class_mask_true.sum() == 0:
            print(f"  {class_name:20s}  -- NO SAMPLES IN VALIDATION SET")
            results[class_name] = {"f1": 0.0, "threshold": threshold, "status": "NO_DATA"}
            continue

        # Compute per-class F1
        tp = ((y_true == idx) & (y_pred == idx)).sum()
        fp = ((y_true != idx) & (y_pred == idx)).sum()
        fn = ((y_true == idx) & (y_pred != idx)).sum()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        status = "PASS" if f1 >= threshold else "FAIL"
        if f1 < threshold:
            all_pass = False

        print(f"  {class_name:20s}  F1={f1:.4f}  (target >= {threshold:.2f})  [{status}]")
        results[class_name] = {
            "f1": round(f1, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "threshold": threshold,
            "status": "PASS" if f1 >= threshold else "FAIL",
            "support": int(class_mask_true.sum()),
        }

    # Overall weighted F1
    precision_w, recall_w, f1_w, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )
    print(f"\n  {'WEIGHTED OVERALL':20s}  F1={f1_w:.4f}  Precision={precision_w:.4f}  Recall={recall_w:.4f}")

    verdict = "PASS -- All exit criteria met" if all_pass else "FAIL -- One or more criteria not met"
    print(f"\n  VERDICT: {verdict}")
    print("=" * 70)

    # Save results to JSON
    output = {
        "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "model": model_name,
        "dataset": str(dataset_path),
        "total_samples": len(df),
        "weighted_f1": round(f1_w, 4),
        "exit_criteria": results,
        "verdict": "PASS" if all_pass else "FAIL",
    }
    results_path = MODELS_DIR / "validation_results.json"
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[+] Results saved to {results_path}")

    return output


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate Sentinel Fabric ML models against realistic traffic datasets."
    )
    parser.add_argument(
        "--dataset", type=str, default=None,
        help="Path to the validation CSV dataset."
    )
    parser.add_argument(
        "--generate-validation", action="store_true",
        help="Generate an independent held-out validation set (seed=99) and evaluate against it."
    )
    args = parser.parse_args()

    if args.generate_validation:
        path = generate_validation_set()
        run_evaluation(str(path))
    elif args.dataset:
        run_evaluation(args.dataset)
    else:
        # Default: generate + evaluate
        if VALIDATION_CSV.exists():
            print(f"[*] Using existing validation set: {VALIDATION_CSV}")
            run_evaluation(str(VALIDATION_CSV))
        else:
            print("[*] No dataset specified. Generating independent validation set...")
            path = generate_validation_set()
            run_evaluation(str(path))


if __name__ == "__main__":
    main()

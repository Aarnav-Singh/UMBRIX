"""Phase 22A — ML Training Pipeline.

Downloads CIC-IDS-2017/2018 dataset, maps features to the Sentinel Fabric
76-dimensional CanonicalEvent feature vector, trains production models,
and exports weight artifacts to backend/models/.

Pipeline Architecture (per @[project-development]):
  Acquire -> Prepare -> Process -> Parse -> Render

Usage:
    python -m scripts.training_pipeline --stage all
    python -m scripts.training_pipeline --stage acquire
    python -m scripts.training_pipeline --stage train_ensemble
    python -m scripts.training_pipeline --stage train_vae
    python -m scripts.training_pipeline --stage evaluate
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import numpy as np
import structlog

logger = structlog.get_logger(__name__)

# ── Constants ────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"
DATA_DIR = PROJECT_ROOT / "data" / "training"
ENSEMBLE_MODEL_PATH = MODELS_DIR / "ensemble_xgb.json"
ENSEMBLE_RF_PATH = MODELS_DIR / "ensemble_rf.pkl"
VAE_MODEL_PATH = MODELS_DIR / "vae.pth"
SCALER_PATH = MODELS_DIR / "feature_scaler.pkl"
METADATA_PATH = MODELS_DIR / "training_metadata.json"

# CIC-IDS-2017 attack labels → Sentinel Fabric attack classes
CIC_LABEL_MAP = {
    "BENIGN": "benign",
    "Bot": "botnet",
    "DDoS": "ddos",
    "DoS GoldenEye": "dos",
    "DoS Hulk": "dos",
    "DoS Slowhttptest": "dos",
    "DoS slowloris": "dos",
    "FTP-Patator": "brute_force",
    "SSH-Patator": "brute_force",
    "Heartbleed": "exploits",
    "Infiltration": "infiltration",
    "PortScan": "port_scan",
    "Web Attack – Brute Force": "web_attack",
    "Web Attack – Sql Injection": "sql_injection",
    "Web Attack – XSS": "web_attack",
    "Web Attack \\x96 Brute Force": "web_attack",
    "Web Attack \\x96 Sql Injection": "sql_injection",
    "Web Attack \\x96 XSS": "web_attack",
}

# Sentinel Fabric attack classes (from ensemble.py)
ATTACK_CLASSES = [
    "benign", "dos", "ddos", "brute_force", "web_attack",
    "infiltration", "botnet", "port_scan", "sql_injection",
    "fuzzers", "backdoors", "exploits", "reconnaissance",
]

# CIC-IDS feature columns → 76-dim Sentinel vector mapping
# Maps CIC-IDS column names to our feature vector positions
CIC_FEATURE_MAP = {
    # Network features (0-15)
    "Source Port": 0,        # src_port
    "Destination Port": 1,   # dst_port
    "Total Fwd Packets": 4,  # packets_in
    "Total Backward Packets": 5,  # packets_out
    "Total Length of Fwd Packets": 2,  # bytes_in
    "Total Length of Bwd Packets": 3,  # bytes_out
    "Flow Duration": 6,      # mapped to bytes_per_packet_in slot
    "Flow Bytes/s": 8,       # total_bytes
    "Flow Packets/s": 9,     # total_packets

    # Behavioral features (16-31) — partially mapped
    "Fwd IAT Mean": 23,      # event_count proxy

    # Temporal features (32-47)
    "Flow IAT Mean": 35,     # inter_event_gap
    "Flow IAT Std": 36,      # events_5m proxy
    "Flow IAT Max": 37,      # events_1h proxy
    "Flow IAT Min": 38,      # unique_ips proxy

    # Payload features (48-63)
    "Fwd Header Length": 51,  # uri_entropy proxy
    "Bwd Header Length": 52,  # payload_entropy proxy
    "Average Packet Size": 53,  # cadence_ms proxy

    # Contextual (64-75) — sparse, mostly zeros
}


def ensure_dirs():
    """Create required directories."""
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)


# ── Stage 1: Acquire ─────────────────────────────────────────────

def acquire_data() -> Path:
    """Download or locate CIC-IDS-2017 dataset.

    Since CIC-IDS is large (~1GB), we support:
    1. Local CSV already present in data/training/
    2. Synthetic generation for development/testing
    """
    csv_path = DATA_DIR / "cicids2017_combined.csv"

    # Check if real dataset exists
    if csv_path.exists():
        logger.info("dataset_found", path=str(csv_path))
        return csv_path

    # Check for any CSV files in the data dir
    existing_csvs = list(DATA_DIR.glob("*.csv"))
    if existing_csvs:
        logger.info("using_existing_csv", path=str(existing_csvs[0]))
        return existing_csvs[0]

    # Generate synthetic training data that mimics CIC-IDS distributions
    logger.info("generating_synthetic_training_data",
                msg="No CIC-IDS CSV found. Generating synthetic data for development.")
    return _generate_synthetic_cicids(csv_path)


def _generate_synthetic_cicids(output_path: Path) -> Path:
    """Generate synthetic training data with realistic CIC-IDS-like distributions.

    This produces labeled data with feature distributions that approximate
    real network traffic patterns, enabling model training without the
    full CIC-IDS download. Replace with real data for production.
    """
    import pandas as pd

    rng = np.random.RandomState(42)
    n_total = 50_000
    records = []

    # Class distribution (approximating CIC-IDS-2017)
    class_dist = {
        "benign": 0.60,
        "dos": 0.12,
        "ddos": 0.08,
        "brute_force": 0.05,
        "port_scan": 0.05,
        "web_attack": 0.03,
        "botnet": 0.02,
        "infiltration": 0.02,
        "exploits": 0.01,
        "sql_injection": 0.01,
        "reconnaissance": 0.01,
    }

    for label, fraction in class_dist.items():
        n = int(n_total * fraction)

        for _ in range(n):
            row = _generate_class_features(label, rng)
            row["Label"] = label
            records.append(row)

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(output_path, index=False)
    logger.info("synthetic_data_generated", samples=len(df), path=str(output_path))
    return output_path


def _generate_class_features(label: str, rng: np.random.RandomState) -> dict:
    """Generate feature vector with class-specific distributions."""
    f = {}

    if label == "benign":
        f["Source Port"] = rng.choice([80, 443, 8080, 8443] + list(range(49152, 65535)))
        f["Destination Port"] = rng.choice([80, 443, 53, 22, 25, 110, 993, 8080])
        f["Total Length of Fwd Packets"] = rng.exponential(500)
        f["Total Length of Bwd Packets"] = rng.exponential(2000)
        f["Total Fwd Packets"] = rng.poisson(5) + 1
        f["Total Backward Packets"] = rng.poisson(5) + 1
        f["Flow Duration"] = rng.exponential(5000000)  # ~5sec avg
        f["Flow Bytes/s"] = rng.exponential(10000)
        f["Flow Packets/s"] = rng.exponential(100)
        f["Flow IAT Mean"] = rng.exponential(100000)
        f["Flow IAT Std"] = rng.exponential(50000)
        f["Flow IAT Max"] = rng.exponential(500000)
        f["Flow IAT Min"] = rng.exponential(10)
        f["Fwd Header Length"] = rng.poisson(40) + 20
        f["Bwd Header Length"] = rng.poisson(40) + 20
        f["Average Packet Size"] = rng.exponential(200)
        f["Fwd IAT Mean"] = rng.exponential(100000)

    elif label in ("dos", "ddos"):
        f["Source Port"] = rng.randint(1024, 65535)
        f["Destination Port"] = rng.choice([80, 443, 53])
        f["Total Length of Fwd Packets"] = rng.exponential(50000)
        f["Total Length of Bwd Packets"] = rng.exponential(1000)
        f["Total Fwd Packets"] = rng.poisson(500) + 100
        f["Total Backward Packets"] = rng.poisson(10)
        f["Flow Duration"] = rng.exponential(1000000)  # short bursts
        f["Flow Bytes/s"] = rng.exponential(500000)  # high rate
        f["Flow Packets/s"] = rng.exponential(5000)  # high rate
        f["Flow IAT Mean"] = rng.exponential(500)  # very low IAT
        f["Flow IAT Std"] = rng.exponential(100)
        f["Flow IAT Max"] = rng.exponential(5000)
        f["Flow IAT Min"] = rng.exponential(1)
        f["Fwd Header Length"] = rng.poisson(60) + 20
        f["Bwd Header Length"] = rng.poisson(20)
        f["Average Packet Size"] = rng.exponential(100)
        f["Fwd IAT Mean"] = rng.exponential(500)

    elif label == "brute_force":
        f["Source Port"] = rng.randint(1024, 65535)
        f["Destination Port"] = rng.choice([22, 3389, 21, 23, 445])
        f["Total Length of Fwd Packets"] = rng.exponential(500)
        f["Total Length of Bwd Packets"] = rng.exponential(300)
        f["Total Fwd Packets"] = rng.poisson(20) + 5
        f["Total Backward Packets"] = rng.poisson(20) + 5
        f["Flow Duration"] = rng.exponential(2000000)
        f["Flow Bytes/s"] = rng.exponential(5000)
        f["Flow Packets/s"] = rng.exponential(50)
        f["Flow IAT Mean"] = rng.exponential(50000)  # regular pacing
        f["Flow IAT Std"] = rng.exponential(5000)  # low variance
        f["Flow IAT Max"] = rng.exponential(100000)
        f["Flow IAT Min"] = rng.exponential(1000)
        f["Fwd Header Length"] = rng.poisson(40) + 20
        f["Bwd Header Length"] = rng.poisson(40) + 20
        f["Average Packet Size"] = rng.exponential(50)
        f["Fwd IAT Mean"] = rng.exponential(50000)

    elif label == "port_scan":
        f["Source Port"] = rng.randint(1024, 65535)
        f["Destination Port"] = rng.randint(1, 65535)  # wide range
        f["Total Length of Fwd Packets"] = rng.exponential(100)  # tiny packets
        f["Total Length of Bwd Packets"] = rng.exponential(50)
        f["Total Fwd Packets"] = rng.poisson(2) + 1
        f["Total Backward Packets"] = rng.poisson(1)
        f["Flow Duration"] = rng.exponential(100000)  # very short
        f["Flow Bytes/s"] = rng.exponential(1000)
        f["Flow Packets/s"] = rng.exponential(1000)  # high packet rate
        f["Flow IAT Mean"] = rng.exponential(1000)  # rapid
        f["Flow IAT Std"] = rng.exponential(200)  # very regular
        f["Flow IAT Max"] = rng.exponential(5000)
        f["Flow IAT Min"] = rng.exponential(1)
        f["Fwd Header Length"] = rng.poisson(40) + 20
        f["Bwd Header Length"] = rng.poisson(20)
        f["Average Packet Size"] = rng.exponential(40)
        f["Fwd IAT Mean"] = rng.exponential(1000)

    elif label in ("web_attack", "sql_injection"):
        f["Source Port"] = rng.randint(1024, 65535)
        f["Destination Port"] = rng.choice([80, 443, 8080])
        f["Total Length of Fwd Packets"] = rng.exponential(5000)  # larger payloads
        f["Total Length of Bwd Packets"] = rng.exponential(2000)
        f["Total Fwd Packets"] = rng.poisson(10) + 3
        f["Total Backward Packets"] = rng.poisson(8) + 2
        f["Flow Duration"] = rng.exponential(3000000)
        f["Flow Bytes/s"] = rng.exponential(20000)
        f["Flow Packets/s"] = rng.exponential(100)
        f["Flow IAT Mean"] = rng.exponential(200000)
        f["Flow IAT Std"] = rng.exponential(100000)
        f["Flow IAT Max"] = rng.exponential(1000000)
        f["Flow IAT Min"] = rng.exponential(100)
        f["Fwd Header Length"] = rng.poisson(200) + 100  # large headers (injections)
        f["Bwd Header Length"] = rng.poisson(100) + 50
        f["Average Packet Size"] = rng.exponential(500)
        f["Fwd IAT Mean"] = rng.exponential(200000)

    else:
        # infiltration, botnet, exploits, reconnaissance, etc.
        f["Source Port"] = rng.randint(1024, 65535)
        f["Destination Port"] = rng.choice([80, 443, 22, 445, 3389, 4444, 8443])
        f["Total Length of Fwd Packets"] = rng.exponential(2000)
        f["Total Length of Bwd Packets"] = rng.exponential(1000)
        f["Total Fwd Packets"] = rng.poisson(15) + 2
        f["Total Backward Packets"] = rng.poisson(10) + 1
        f["Flow Duration"] = rng.exponential(8000000)
        f["Flow Bytes/s"] = rng.exponential(15000)
        f["Flow Packets/s"] = rng.exponential(200)
        f["Flow IAT Mean"] = rng.exponential(300000)
        f["Flow IAT Std"] = rng.exponential(200000)
        f["Flow IAT Max"] = rng.exponential(2000000)
        f["Flow IAT Min"] = rng.exponential(100)
        f["Fwd Header Length"] = rng.poisson(60) + 20
        f["Bwd Header Length"] = rng.poisson(40) + 20
        f["Average Packet Size"] = rng.exponential(200)
        f["Fwd IAT Mean"] = rng.exponential(300000)

    return f


# ── Stage 2: Prepare ─────────────────────────────────────────────

def prepare_data(csv_path: Path) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Map CIC-IDS features to 76-dim Sentinel feature vectors.

    Returns (X_train, X_test, y_train, y_test).
    """
    import pandas as pd
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    import joblib

    logger.info("preparing_data", csv=str(csv_path))
    df = pd.read_csv(csv_path)

    # Clean column names
    df.columns = df.columns.str.strip()

    # Map labels
    if "Label" in df.columns:
        # Direct mapped labels (synthetic or pre-mapped)
        if df["Label"].iloc[0] in ATTACK_CLASSES:
            df["mapped_label"] = df["Label"]
        else:
            df["mapped_label"] = df["Label"].map(CIC_LABEL_MAP).fillna("benign")
    else:
        raise ValueError("No 'Label' column in dataset")

    # Encode labels to integers
    label_to_idx = {cls: i for i, cls in enumerate(ATTACK_CLASSES)}
    df["label_idx"] = df["mapped_label"].map(label_to_idx).fillna(0).astype(int)

    # Build 76-dim feature vectors
    feature_cols = list(CIC_FEATURE_MAP.keys())
    available_cols = [c for c in feature_cols if c in df.columns]

    X_76 = np.zeros((len(df), 76), dtype=np.float32)
    for col in available_cols:
        idx = CIC_FEATURE_MAP[col]
        vals = pd.to_numeric(df[col], errors="coerce").fillna(0).values
        # Clip extreme values
        p99 = np.percentile(np.abs(vals[vals != 0]) + 1e-10, 99) if np.any(vals != 0) else 1.0
        vals = np.clip(vals, -p99 * 10, p99 * 10)
        X_76[:, idx] = vals.astype(np.float32)

    y = df["label_idx"].values

    # Remove rows with all-zero features (if any)
    nonzero_mask = np.any(X_76 != 0, axis=1)
    X_76 = X_76[nonzero_mask]
    y = y[nonzero_mask]

    # Fit scaler and transform
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_76)

    # Replace NaN/Inf from scaling
    X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=0.0, neginf=0.0)

    # Save scaler for inference
    joblib.dump(scaler, SCALER_PATH)
    logger.info("scaler_saved", path=str(SCALER_PATH))

    # Stratified split
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )

    logger.info("data_prepared",
                train_samples=len(X_train),
                test_samples=len(X_test),
                n_classes=len(np.unique(y)),
                feature_dim=X_76.shape[1])

    return X_train, X_test, y_train, y_test


# ── Stage 3: Process (Train) ─────────────────────────────────────

def train_ensemble(X_train: np.ndarray, y_train: np.ndarray) -> None:
    """Train XGBoost + RandomForest on 76-dim feature vectors."""
    import joblib

    # ── XGBoost ──
    try:
        import xgboost as xgb

        logger.info("training_xgboost", n_samples=len(X_train))
        dtrain = xgb.DMatrix(X_train, label=y_train)
        params = {
            "objective": "multi:softprob",
            "num_class": len(ATTACK_CLASSES),
            "max_depth": 8,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "eval_metric": "mlogloss",
            "tree_method": "hist",
            "seed": 42,
            "verbosity": 0,
        }
        model = xgb.train(params, dtrain, num_boost_round=200)
        model.save_model(str(ENSEMBLE_MODEL_PATH))
        logger.info("xgboost_saved", path=str(ENSEMBLE_MODEL_PATH))

    except ImportError:
        logger.warning("xgboost_not_available", msg="Skipping XGBoost, training RF only")

    # ── RandomForest (76-dim, always available) ──
    from sklearn.ensemble import RandomForestClassifier

    logger.info("training_random_forest", n_samples=len(X_train))
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    rf.fit(X_train, y_train)
    joblib.dump(rf, ENSEMBLE_RF_PATH)
    logger.info("random_forest_saved", path=str(ENSEMBLE_RF_PATH))


def train_vae(X_train: np.ndarray, y_train: np.ndarray) -> None:
    """Train VAE on benign-only data for anomaly detection."""
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import DataLoader, TensorDataset

    # Filter benign-only for unsupervised training
    benign_mask = y_train == 0  # 0 = benign
    X_benign = X_train[benign_mask]

    if len(X_benign) < 100:
        logger.warning("insufficient_benign_data", count=len(X_benign))
        return

    logger.info("training_vae", benign_samples=len(X_benign))

    # Pad to 128 dims (VAE input_dim=128)
    X_padded = np.zeros((len(X_benign), 128), dtype=np.float32)
    X_padded[:, :76] = X_benign

    dataset = TensorDataset(torch.tensor(X_padded))
    loader = DataLoader(dataset, batch_size=64, shuffle=True)

    # Import the actual model class
    sys.path.insert(0, str(PROJECT_ROOT))
    from app.ml.vae import AnomalyVAE

    model = AnomalyVAE(input_dim=128, latent_dim=16)
    optimizer = optim.Adam(model.parameters(), lr=1e-3)

    # Train
    model.train()
    for epoch in range(50):
        total_loss = 0.0
        for (batch,) in loader:
            optimizer.zero_grad()
            recon, mu, logvar = model(batch)

            # Reconstruction + KL divergence loss
            recon_loss = nn.functional.mse_loss(recon, batch, reduction="sum")
            kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
            loss = recon_loss + kl_loss

            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        if (epoch + 1) % 10 == 0:
            avg_loss = total_loss / len(X_benign)
            logger.info("vae_epoch", epoch=epoch + 1, avg_loss=round(avg_loss, 4))

    torch.save(model.state_dict(), VAE_MODEL_PATH)
    logger.info("vae_saved", path=str(VAE_MODEL_PATH))


# ── Stage 4: Parse/Render (Evaluate) ─────────────────────────────

def evaluate_models(X_test: np.ndarray, y_test: np.ndarray) -> dict:
    """Evaluate trained models. Returns metrics dict.

    Per @[evaluation]: Multi-dimensional rubric with stratified test sets.
    """
    from sklearn.metrics import (
        classification_report, roc_auc_score, confusion_matrix,
        precision_recall_fscore_support,
    )
    import joblib

    results = {}

    # ── Evaluate RF ──
    if ENSEMBLE_RF_PATH.exists():
        rf = joblib.load(ENSEMBLE_RF_PATH)
        y_pred = rf.predict(X_test)
        y_proba = rf.predict_proba(X_test)

        # Multi-class AUC (OvR)
        try:
            auc = roc_auc_score(y_test, y_proba, multi_class="ovr", average="weighted")
        except ValueError:
            auc = 0.0

        precision, recall, f1, support = precision_recall_fscore_support(
            y_test, y_pred, average="weighted", zero_division=0
        )

        # FPR: false positive rate for non-benign classes
        cm = confusion_matrix(y_test, y_pred)
        if cm.shape[0] > 1:
            # FP for benign class = sum of column 0 minus TP
            tp_benign = cm[0, 0] if cm.shape[0] > 0 else 0
            fp_benign = cm[:, 0].sum() - tp_benign
            tn_benign = cm.sum() - cm[0, :].sum() - cm[:, 0].sum() + tp_benign
            fpr = fp_benign / (fp_benign + tn_benign) if (fp_benign + tn_benign) > 0 else 0
        else:
            fpr = 0.0

        results["random_forest"] = {
            "auc_weighted": round(float(auc), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1": round(float(f1), 4),
            "fpr_benign": round(float(fpr), 4),
            "test_samples": int(len(y_test)),
        }

        logger.info("rf_evaluation",
                     auc=round(auc, 4),
                     precision=round(precision, 4),
                     recall=round(recall, 4),
                     f1=round(f1, 4),
                     fpr=round(fpr, 4))

        # Per-class report
        report = classification_report(
            y_test, y_pred,
            target_names=[ATTACK_CLASSES[i] for i in sorted(np.unique(y_test))],
            output_dict=True,
            zero_division=0,
        )
        results["per_class_report"] = report

    # ── Evaluate XGBoost ──
    if ENSEMBLE_MODEL_PATH.exists():
        try:
            import xgboost as xgb
            model = xgb.Booster()
            model.load_model(str(ENSEMBLE_MODEL_PATH))
            dtest = xgb.DMatrix(X_test)
            y_proba = model.predict(dtest)
            y_pred = np.argmax(y_proba, axis=1)

            auc = roc_auc_score(y_test, y_proba, multi_class="ovr", average="weighted")
            precision, recall, f1, _ = precision_recall_fscore_support(
                y_test, y_pred, average="weighted", zero_division=0
            )

            results["xgboost"] = {
                "auc_weighted": round(float(auc), 4),
                "precision": round(float(precision), 4),
                "recall": round(float(recall), 4),
                "f1": round(float(f1), 4),
            }
            logger.info("xgb_evaluation", auc=round(auc, 4), f1=round(f1, 4))
        except ImportError:
            pass

    # Save metadata
    metadata = {
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "feature_dim": 76,
        "n_classes": len(ATTACK_CLASSES),
        "attack_classes": ATTACK_CLASSES,
        "results": results,
        "models": {
            "ensemble_rf": str(ENSEMBLE_RF_PATH) if ENSEMBLE_RF_PATH.exists() else None,
            "ensemble_xgb": str(ENSEMBLE_MODEL_PATH) if ENSEMBLE_MODEL_PATH.exists() else None,
            "vae": str(VAE_MODEL_PATH) if VAE_MODEL_PATH.exists() else None,
            "scaler": str(SCALER_PATH) if SCALER_PATH.exists() else None,
        },
    }
    with open(METADATA_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
    logger.info("metadata_saved", path=str(METADATA_PATH))

    return results


# ── Orchestrator ──────────────────────────────────────────────────

def run_full_pipeline():
    """Execute the full training pipeline: acquire → prepare → train → evaluate."""
    ensure_dirs()

    # Stage 1: Acquire
    logger.info("=== Stage 1: Acquire ===")
    csv_path = acquire_data()

    # Stage 2: Prepare
    logger.info("=== Stage 2: Prepare ===")
    X_train, X_test, y_train, y_test = prepare_data(csv_path)

    # Stage 3a: Train Ensemble
    logger.info("=== Stage 3a: Train Ensemble ===")
    train_ensemble(X_train, y_train)

    # Stage 3b: Train VAE
    logger.info("=== Stage 3b: Train VAE ===")
    train_vae(X_train, y_train)

    # Stage 4: Evaluate
    logger.info("=== Stage 4: Evaluate ===")
    results = evaluate_models(X_test, y_test)

    # Check exit criteria
    rf_results = results.get("random_forest", {})
    auc = rf_results.get("auc_weighted", 0)
    fpr = rf_results.get("fpr_benign", 1.0)

    logger.info("=== Pipeline Complete ===",
                auc=auc,
                fpr=fpr,
                auc_target=">0.85",
                fpr_target="<0.08")

    if auc >= 0.85:
        logger.info("EXIT_CRITERION_MET: AUC > 0.85 [PASS]")
    else:
        logger.warning("EXIT_CRITERION_NOT_MET: AUC < 0.85", auc=auc)

    if fpr <= 0.08:
        logger.info("EXIT_CRITERION_MET: FPR < 8% [PASS]")
    else:
        logger.warning("EXIT_CRITERION_NOT_MET: FPR > 8%", fpr=fpr)

    return results


def main():
    parser = argparse.ArgumentParser(description="Sentinel Fabric V2 ML Training Pipeline")
    parser.add_argument("--stage", default="all",
                        choices=["all", "acquire", "prepare", "train_ensemble", "train_vae", "evaluate"],
                        help="Pipeline stage to run")
    args = parser.parse_args()

    ensure_dirs()

    if args.stage == "all":
        run_full_pipeline()
    elif args.stage == "acquire":
        acquire_data()
    elif args.stage == "prepare":
        csv_path = acquire_data()
        prepare_data(csv_path)
    elif args.stage == "train_ensemble":
        csv_path = acquire_data()
        X_train, X_test, y_train, y_test = prepare_data(csv_path)
        train_ensemble(X_train, y_train)
    elif args.stage == "train_vae":
        csv_path = acquire_data()
        X_train, X_test, y_train, y_test = prepare_data(csv_path)
        train_vae(X_train, y_train)
    elif args.stage == "evaluate":
        csv_path = acquire_data()
        _, X_test, _, y_test = prepare_data(csv_path)
        evaluate_models(X_test, y_test)


if __name__ == "__main__":
    main()

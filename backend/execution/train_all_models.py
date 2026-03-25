#!/usr/bin/env python3
"""
Sentinel Fabric V2 — Unified Model Training Script
====================================================
Generates trained weights for all 4 ML streams and saves them to
``backend/models/`` so the pipeline no longer falls back to random init.

Usage (from the backend/ directory):
    python execution/train_all_models.py

Requirements: install the backend dev dependencies first:
    pip install -e ".[dev]"
    
Outputs
-------
models/vae.pth            — VAE anomaly autoencoder
models/temporal.pth       — Temporal Transformer weights
models/meta_learner.txt   — LightGBM Booster model file
models/ensemble/          — XGBoost Booster + RF pickle (ensemble stream)
"""
from __future__ import annotations

import json
import math
import os
import pickle
import sys
import time
from pathlib import Path

import numpy as np

# --------------------------------------------------------------------------- #
# Path bootstrapping — allow running from backend/ or backend/execution/
# --------------------------------------------------------------------------- #
_SCRIPT_DIR = Path(__file__).resolve().parent
_BACKEND_DIR = _SCRIPT_DIR.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

MODELS_DIR = _BACKEND_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)
(MODELS_DIR / "ensemble").mkdir(exist_ok=True)

# --------------------------------------------------------------------------- #
# Attack-class labels (must match app/ml/ensemble.py)
# --------------------------------------------------------------------------- #
ATTACK_CLASSES = [
    "benign", "dos", "ddos", "brute_force", "web_attack",
    "infiltration", "botnet", "port_scan", "sql_injection",
    "fuzzers", "backdoors", "exploits", "reconnaissance",
]
N_CLASSES = len(ATTACK_CLASSES)
N_TABULAR = 76   # Feature vector width (must match feature_extractor.py)
N_META_IN = 14   # 5 stream scores + 9 context features


# =========================================================================== #
# Dataset generation helpers
# =========================================================================== #

def _make_classification_dataset(
    n_samples: int = 6000,
    n_features: int = N_TABULAR,
    rng: np.random.RandomState | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Generates a labeled tabular dataset that mimics real IDS feature patterns.

    Each attack class has class-specific feature signatures so classifiers
    can learn discriminative boundaries rather than random noise.
    """
    rng = rng or np.random.RandomState(42)
    samples_per_class = n_samples // N_CLASSES

    X_list, y_list = [], []

    for cls_idx, cls_name in enumerate(ATTACK_CLASSES):
        n = samples_per_class
        # Base: Gaussian noise
        X_cls = rng.randn(n, n_features) * 0.3

        # Network features (idx 0-15)
        if cls_name == "benign":
            X_cls[:, 2] = rng.exponential(500, n)      # bytes_in: moderate
            X_cls[:, 3] = rng.exponential(500, n)      # bytes_out: moderate
            X_cls[:, 12] = 1.0                         # TCP dominant
        elif cls_name in ("dos", "ddos"):
            X_cls[:, 2] = rng.exponential(80_000, n)   # high bytes_in
            X_cls[:, 4] = rng.exponential(10_000, n)   # high packets_in
            X_cls[:, 12] = rng.choice([0, 1], n)       # mixed TCP/UDP
        elif cls_name == "port_scan":
            X_cls[:, 2] = rng.exponential(50, n)       # very low bytes
            X_cls[:, 0] = rng.uniform(0, 65535, n)     # random src_port
            X_cls[:, 1] = rng.uniform(1, 65535, n)     # random dst_port
        elif cls_name == "brute_force":
            X_cls[:, 1] = rng.choice([22, 23, 3389, 5900], n).astype(float)  # common admin ports
            X_cls[:, 5] = rng.exponential(100, n)      # high packets (retry)
        elif cls_name == "web_attack":
            X_cls[:, 66] = rng.uniform(4.5, 7.5, n)   # high URI entropy
            X_cls[:, 67] = rng.uniform(3.5, 6.0, n)   # high payload entropy
        elif cls_name == "sql_injection":
            X_cls[:, 66] = rng.uniform(5.0, 8.0, n)   # very high URI entropy
            X_cls[:, 1] = np.full(n, 80.0)             # HTTP port
        elif cls_name in ("infiltration", "backdoors"):
            X_cls[:, 67] = rng.uniform(5.0, 8.0, n)   # encrypted payload
            X_cls[:, 15] = 1.0                         # known malicious port flag
        elif cls_name == "botnet":
            X_cls[:, 68] = rng.uniform(5, 500, n)     # regular cadence_ms
            X_cls[:, 2] = rng.exponential(200, n)
        elif cls_name in ("fuzzers", "exploits"):
            X_cls[:, 67] = rng.uniform(6.0, 8.0, n)   # very high payload entropy
            X_cls[:, 64] = rng.uniform(0.3, 1.0, n)   # flags anomalous source
        elif cls_name == "reconnaissance":
            X_cls[:, 2] = rng.exponential(30, n)       # tiny bytes
            X_cls[:, 4] = rng.exponential(3000, n)     # many packets

        # Temporal features (idx 32-47):
        X_cls[:, 32] = rng.uniform(0, 23, n)           # hour
        X_cls[:, 33] = (X_cls[:, 32] < 6) | (X_cls[:, 32] > 22)  # off-hours flag

        # Ensure values are clipped to reasonable range
        X_cls = np.clip(X_cls, -10, 100_000)

        X_list.append(X_cls)
        y_list.append(np.full(n, cls_idx, dtype=int))

    X = np.vstack(X_list)
    y = np.concatenate(y_list)

    # Shuffle
    perm = rng.permutation(len(y))
    return X[perm], y[perm]


def _make_anomaly_dataset(
    n_benign: int = 3000,
    n_anomaly: int = 1000,
    n_features: int = 128,
    rng: np.random.RandomState | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate train (benign-only) and test data for autoencoder training."""
    rng = rng or np.random.RandomState(42)

    # Normal traffic: low-amplitude Gaussian
    X_normal = rng.randn(n_benign, n_features) * 0.5

    # Anomalous: high-amplitude Gaussian (reconstruction error should be higher)
    X_anomaly = rng.randn(n_anomaly, n_features) * 3.0 + 5.0

    return X_normal, X_anomaly


def _make_meta_dataset(
    n_samples: int = 4000,
    rng: np.random.RandomState | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate (stream_scores + context_features, is_threat) dataset for LightGBM."""
    rng = rng or np.random.RandomState(42)
    n_pos = n_samples // 2
    n_neg = n_samples - n_pos

    # Threat cases — stream scores should be high
    pos_streams = rng.beta(8, 2, (n_pos, 5))    # peaked towards 1.0
    pos_context = rng.randn(n_pos, 9) * 0.3 + 0.5
    X_pos = np.hstack([pos_streams, pos_context])

    # Benign cases — stream scores should be low
    neg_streams = rng.beta(2, 8, (n_neg, 5))    # peaked towards 0.0
    neg_context = rng.randn(n_neg, 9) * 0.3 + 0.5
    X_neg = np.hstack([neg_streams, neg_context])

    X = np.vstack([X_pos, X_neg])
    y = np.concatenate([np.ones(n_pos), np.zeros(n_neg)])
    perm = rng.permutation(len(y))
    return X[perm], y[perm]


# =========================================================================== #
# Stream 1 — Ensemble (XGBoost + RF)
# =========================================================================== #

def train_ensemble(rng: np.random.RandomState) -> None:
    print("\n[1/4] Training Ensemble Classifier (Stream 1)...")
    t0 = time.perf_counter()

    X, y = _make_classification_dataset(n_samples=7000, rng=rng)
    split = int(len(y) * 0.8)
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]

    # --- XGBoost ---
    try:
        import xgboost as xgb
        dtrain = xgb.DMatrix(X_train, label=y_train)
        dtest = xgb.DMatrix(X_test, label=y_test)
        params = {
            "objective": "multi:softprob",
            "num_class": N_CLASSES,
            "max_depth": 6,
            "learning_rate": 0.05,
            "n_estimators": 200,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "eval_metric": "mlogloss",
            "seed": 42,
            "verbosity": 0,
        }
        booster = xgb.train(
            params, dtrain,
            num_boost_round=200,
            evals=[(dtest, "test")],
            early_stopping_rounds=15,
            verbose_eval=False,
        )
        out_path = str(MODELS_DIR / "ensemble" / "xgb_model.json")
        booster.save_model(out_path)
        preds = np.argmax(booster.predict(dtest), axis=1)
        acc = np.mean(preds == y_test)
        print(f"  XGBoost   — saved to {out_path}  acc={acc:.3f}")
    except ImportError:
        print("  XGBoost   — not installed, skipping XGB model (RF fallback still trained)")

    # --- Sklearn RandomForest (always trained, used as primary fallback) ---
    from sklearn.ensemble import RandomForestClassifier
    rf = RandomForestClassifier(n_estimators=150, max_depth=12, random_state=42, n_jobs=-1)
    rf.fit(X_train[:, :16], y_train)   # RF uses 16-feature subset (matches ensemble.py)
    rf_acc = np.mean(rf.predict(X_test[:, :16]) == y_test)
    rf_path = str(MODELS_DIR / "ensemble" / "rf_model.pkl")
    with open(rf_path, "wb") as f:
        pickle.dump(rf, f)
    print(f"  RF        — saved to {rf_path}  acc={rf_acc:.3f}")

    print(f"  Done in {time.perf_counter() - t0:.1f}s")


# =========================================================================== #
# Stream 2 — VAE Anomaly Detector
# =========================================================================== #

def train_vae(rng: np.random.RandomState) -> None:
    print("\n[2/4] Training VAE Anomaly Detector (Stream 2)...")
    t0 = time.perf_counter()

    try:
        import torch
        import torch.nn as nn
        import torch.optim as optim
        from app.ml.vae import AnomalyVAE
    except ImportError as e:
        print(f"  Skipped — missing dependency: {e}")
        return

    X_normal, X_anomaly = _make_anomaly_dataset(n_benign=4000, n_anomaly=1000, rng=rng)
    X_train = torch.tensor(X_normal, dtype=torch.float32)

    model = AnomalyVAE(input_dim=128, latent_dim=16)
    optimizer = optim.Adam(model.parameters(), lr=1e-3)

    # VAE loss = reconstruction loss + KL divergence
    def vae_loss(recon: torch.Tensor, x: torch.Tensor, mu: torch.Tensor, logvar: torch.Tensor) -> torch.Tensor:
        recon_loss = nn.functional.mse_loss(recon, x, reduction="mean")
        kl = -0.5 * torch.mean(1 + logvar - mu.pow(2) - logvar.exp())
        return recon_loss + 0.001 * kl

    dataset = torch.utils.data.TensorDataset(X_train)
    loader = torch.utils.data.DataLoader(dataset, batch_size=128, shuffle=True)

    model.train()
    for epoch in range(30):
        epoch_loss = 0.0
        for (batch,) in loader:
            optimizer.zero_grad()
            recon, mu, logvar = model(batch)
            loss = vae_loss(recon, batch, mu, logvar)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
        if (epoch + 1) % 10 == 0:
            print(f"  Epoch {epoch+1:02d}/30 — loss={epoch_loss/len(loader):.5f}")

    # Validate: anomaly MSE should be higher than benign MSE
    model.eval()
    with torch.no_grad():
        X_b = torch.tensor(X_normal[:200], dtype=torch.float32)
        X_a = torch.tensor(X_anomaly[:200], dtype=torch.float32)
        recon_b, _, _ = model(X_b)
        recon_a, _, _ = model(X_a)
        mse_benign = nn.functional.mse_loss(recon_b, X_b).item()
        mse_anomaly = nn.functional.mse_loss(recon_a, X_a).item()
    print(f"  Validation — benign_mse={mse_benign:.4f}  anomaly_mse={mse_anomaly:.4f}  (ratio={mse_anomaly/max(mse_benign,1e-9):.1f}x)")

    out_path = str(MODELS_DIR / "vae.pth")
    torch.save(model.state_dict(), out_path)
    print(f"  Saved to {out_path}  (size: {Path(out_path).stat().st_size // 1024}KB)")
    print(f"  Done in {time.perf_counter() - t0:.1f}s")


# =========================================================================== #
# Stream 4 — Temporal Transformer
# =========================================================================== #

def train_temporal(rng: np.random.RandomState) -> None:
    print("\n[3/4] Training Temporal Transformer (Stream 4)...")
    t0 = time.perf_counter()

    try:
        import torch
        import torch.nn as nn
        import torch.optim as optim
        from app.ml.temporal import TemporalTransformer
    except ImportError as e:
        print(f"  Skipped — missing dependency: {e}")
        return

    D_MODEL = 64
    MAX_SEQ = 50

    def _make_seq_dataset(n: int = 3000) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Generate (batch, seq_len, d_model) sequences.
        Label=1 if the last event has high anomaly feature values.
        """
        X_batches, y_batches = [], []
        for _ in range(n):
            seq_len = rng.randint(5, MAX_SEQ + 1)
            # Normal sequence: low amplitude
            seq = rng.randn(seq_len, D_MODEL).astype(np.float32) * 0.3
            label = 0.0
            # 40% chance the last event is anomalous (high amplitude)
            if rng.rand() < 0.4:
                seq[-1] = rng.randn(D_MODEL).astype(np.float32) * 3.0 + 2.0
                label = 1.0
            # Pad to MAX_SEQ
            pad = np.zeros((MAX_SEQ - seq_len, D_MODEL), dtype=np.float32)
            seq_padded = np.vstack([pad, seq])
            X_batches.append(seq_padded)
            y_batches.append(label)
        return (
            torch.tensor(np.array(X_batches), dtype=torch.float32),
            torch.tensor(y_batches, dtype=torch.float32),
        )

    X_all, y_all = _make_seq_dataset(3000)
    split = int(len(y_all) * 0.8)
    X_train, X_test = X_all[:split], X_all[split:]
    y_train, y_test = y_all[:split], y_all[split:]

    model = TemporalTransformer(d_model=D_MODEL, nhead=4, num_layers=2, max_seq_len=MAX_SEQ)
    optimizer = optim.Adam(model.parameters(), lr=5e-4)
    criterion = nn.BCELoss()

    dataset = torch.utils.data.TensorDataset(X_train, y_train)
    loader = torch.utils.data.DataLoader(dataset, batch_size=64, shuffle=True)

    model.train()
    for epoch in range(20):
        epoch_loss = 0.0
        for X_b, y_b in loader:
            optimizer.zero_grad()
            preds = model(X_b).squeeze(1)
            loss = criterion(preds, y_b)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            epoch_loss += loss.item()
        if (epoch + 1) % 5 == 0:
            print(f"  Epoch {epoch+1:02d}/20 — loss={epoch_loss/len(loader):.5f}")

    # Validation accuracy
    model.eval()
    with torch.no_grad():
        test_preds = (model(X_test).squeeze(1) > 0.5).float()
        acc = torch.mean((test_preds == y_test).float()).item()
    print(f"  Validation accuracy: {acc:.3f}")

    out_path = str(MODELS_DIR / "temporal.pth")
    torch.save(model.state_dict(), out_path)
    print(f"  Saved to {out_path}  (size: {Path(out_path).stat().st_size // 1024}KB)")
    print(f"  Done in {time.perf_counter() - t0:.1f}s")


# =========================================================================== #
# Meta-Learner — LightGBM Stream Fusion
# =========================================================================== #

def train_meta_learner(rng: np.random.RandomState) -> None:
    print("\n[4/4] Training Meta-Learner (LightGBM stream fusion)...")
    t0 = time.perf_counter()

    try:
        import lightgbm as lgb
    except ImportError:
        print("  Skipped — lightgbm not installed")
        return

    X, y = _make_meta_dataset(n_samples=5000, rng=rng)
    split = int(len(y) * 0.8)
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]

    feature_names = [
        "score_ensemble", "score_vae", "score_hst", "score_temporal", "score_adversarial",
        "hour", "asset_criticality", "campaign_stage", "inter_event_gap",
        "events_1h", "unique_ips_1h", "geo_risk", "severity_num", "posture_delta",
    ]

    dtrain = lgb.Dataset(X_train, label=y_train, feature_name=feature_names)
    dtest = lgb.Dataset(X_test, label=y_test, reference=dtrain)

    params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "learning_rate": 0.05,
        "num_leaves": 31,
        "max_depth": 6,
        "min_data_in_leaf": 20,
        "verbosity": -1,
        "seed": 42,
    }

    callbacks = [lgb.early_stopping(stopping_rounds=20, verbose=False)]
    booster = lgb.train(
        params, dtrain,
        num_boost_round=300,
        valid_sets=[dtest],
        callbacks=callbacks,
    )

    preds = booster.predict(X_test)
    from sklearn.metrics import roc_auc_score, accuracy_score
    auc = roc_auc_score(y_test, preds)
    acc = accuracy_score(y_test, (preds > 0.5).astype(int))
    print(f"  Validation — AUC={auc:.4f}  Acc={acc:.4f}")

    out_path = str(MODELS_DIR / "meta_learner.txt")
    booster.save_model(out_path)
    print(f"  Saved to {out_path}  (size: {Path(out_path).stat().st_size // 1024}KB)")
    print(f"  Done in {time.perf_counter() - t0:.1f}s")


# =========================================================================== #
# Main entry point
# =========================================================================== #

def main() -> None:
    print("=" * 60)
    print("Sentinel Fabric V2 — Model Training")
    print(f"Output directory: {MODELS_DIR}")
    print("=" * 60)

    rng = np.random.RandomState(42)
    total_start = time.perf_counter()

    train_ensemble(rng)
    train_vae(rng)
    train_temporal(rng)
    train_meta_learner(rng)

    print("\n" + "=" * 60)
    print(f"All models trained in {time.perf_counter() - total_start:.1f}s")
    print("\nModel files:")
    for f in sorted(MODELS_DIR.rglob("*")):
        if f.is_file():
            print(f"  {f.relative_to(MODELS_DIR)}  ({f.stat().st_size // 1024}KB)")
    print("=" * 60)


if __name__ == "__main__":
    main()

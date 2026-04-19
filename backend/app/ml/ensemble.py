"""Stream 1: Supervised Ensemble — XGBoost + RandomForest.

Trained on CIC-IDS-2017/2018 mapped to UMBRIX's 76-dim
feature vector. Uses real model artifacts when available, falls
back to a synthetic RF for development.

Model loading priority:
  1. XGBoost (models/ensemble_xgb.json) — highest accuracy
  2. Trained RF (models/ensemble_rf.pkl) — full 76-dim features
  3. Synthetic RF fallback — 16-dim, for development only
"""
from __future__ import annotations

import os

import numpy as np
from sklearn.ensemble import RandomForestClassifier

import structlog

logger = structlog.get_logger(__name__)

# Attack class labels from CIC-IDS + UNSW-NB15
ATTACK_CLASSES = [
    "benign", "dos", "ddos", "brute_force", "web_attack",
    "infiltration", "botnet", "port_scan", "sql_injection",
    "fuzzers", "backdoors", "exploits", "reconnaissance",
]

# Feature names for the first 16 dims (used by SHAP and synthetic fallback)
FEATURE_NAMES_16 = [
    "bytes_in", "bytes_out", "packets_in", "packets_out",
    "src_port", "dst_port", "duration", "protocol_tcp",
    "protocol_udp", "severity_num", "action_alert", "action_block",
    "uri_entropy", "payload_entropy", "cadence_ms", "geo_risk",
]

# Full 76-dim feature block names
FEATURE_BLOCKS = {
    "network": list(range(0, 16)),
    "entity_behavioral": list(range(16, 32)),
    "temporal": list(range(32, 48)),
    "payload_signature": list(range(48, 64)),
    "contextual": list(range(64, 76)),
}

# Default model directory
_MODELS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "models",
)


def _build_synthetic_forest() -> RandomForestClassifier:
    """Build a small RF trained on synthetic feature distributions.

    This is the DEVELOPMENT FALLBACK — only used when no trained
    model artifacts exist. Uses 16-dim features only.
    """
    rng = np.random.RandomState(42)
    n_samples = 500
    n_features = 16
    n_classes = len(ATTACK_CLASSES)

    X = rng.randn(n_samples, n_features)
    y = np.zeros(n_samples, dtype=int)

    samples_per_class = n_samples // n_classes

    for cls_idx in range(n_classes):
        start = cls_idx * samples_per_class
        end = start + samples_per_class
        y[start:end] = cls_idx

        if cls_idx == 0:  # benign: low bytes, normal ports
            X[start:end, 0] = rng.exponential(100, samples_per_class)
            X[start:end, 1] = rng.exponential(100, samples_per_class)
        elif cls_idx in (1, 2):  # dos/ddos: high packets, high bytes
            X[start:end, 0] = rng.exponential(50000, samples_per_class)
            X[start:end, 3] = rng.exponential(1000, samples_per_class)
        elif cls_idx == 3:  # brute_force
            X[start:end, 9] = rng.uniform(3, 5, samples_per_class)
            X[start:end, 11] = 1.0
        elif cls_idx == 7:  # port_scan
            X[start:end, 5] = rng.uniform(1, 65535, samples_per_class)
            X[start:end, 0] = rng.exponential(10, samples_per_class)
        elif cls_idx == 8:  # sql_injection
            X[start:end, 12] = rng.uniform(4, 7, samples_per_class)
        elif cls_idx in (5, 10):  # infiltration, backdoors
            X[start:end, 13] = rng.uniform(5, 8, samples_per_class)
        elif cls_idx == 12:  # reconnaissance
            X[start:end, 0] = rng.exponential(5, samples_per_class)
            X[start:end, 5] = rng.choice([22, 80, 443, 445, 3389], samples_per_class)

    clf = RandomForestClassifier(
        n_estimators=30, max_depth=8, random_state=42, n_jobs=1,
    )
    clf.fit(X, y)
    return clf


class EnsembleClassifier:
    """XGBoost + RandomForest stacked ensemble for known attack detection."""

    def __init__(self) -> None:
        self._xgb_model = None
        self._nn_model = None
        self._meta_model = None
        self._rf_model: RandomForestClassifier | None = None
        self._scaler = None
        self._loaded = False
        self._model_type = "none"  # "xgboost", "trained_rf", "synthetic_rf"
        self._feature_dim = 16  # 16 for synthetic, 76 for trained

    def load_models(self, model_dir: str | None = None) -> None:
        """Load trained models from local store, with cascading fallback.

        Priority: XGBoost -> Trained RF (76-dim) -> Synthetic RF (16-dim)
        """
        models_dir = model_dir or _MODELS_DIR

        # Try loading the feature scaler first (JSON preferred for security)
        scaler_path = os.path.join(models_dir, "feature_scaler.json")
        if os.path.exists(scaler_path):
            try:
                import json
                with open(scaler_path, "r") as f:
                    data = json.load(f)
                    # Reconstruct a simple scaler object to avoid joblib/pickle RCE
                    class SimpleScaler:
                        def __init__(self, mean, scale):
                            self.mean = np.array(mean)
                            self.scale = np.array(scale)
                        def transform(self, X):
                            return (X - self.mean) / self.scale
                    self._scaler = SimpleScaler(data["mean"], data["scale"])
                logger.info("feature_scaler_json_loaded", path=scaler_path)
            except Exception as exc:
                logger.warning("scaler_json_load_failed", error=str(exc))
        else:
            # Legacy fallback (deprecated/unsafe)
            scaler_path_legacy = os.path.join(models_dir, "feature_scaler.pkl")
            if os.path.exists(scaler_path_legacy):
                logger.warning("unsafe_scaler_pickle_detected", msg="Migrate to feature_scaler.json")

        # Priority 1: XGBoost
        xgb_path = os.path.join(models_dir, "ensemble_xgb.json")
        if os.path.exists(xgb_path):
            try:
                import xgboost as xgb
                self._xgb_model = xgb.Booster()
                self._xgb_model.load_model(xgb_path)
                self._loaded = True
                self._model_type = "xgboost"
                self._feature_dim = 76
                logger.info("ensemble_xgboost_loaded", path=xgb_path)
                return
            except (ImportError, Exception) as exc:
                logger.warning("xgboost_load_failed", error=str(exc))

        # Priority 2: Trained RandomForest (JSON/ONNX preferred, skipping unsafe .pkl)
        # Note: We skip ensemble_rf.pkl due to security concerns (HIGH-17).
        # Fall back to synthetic forest if XGBoost is missing.
        rf_path_json = os.path.join(models_dir, "ensemble_rf.json")
        if os.path.exists(rf_path_json):
            # Future: implement secure JSON-based RF traversal
            pass

        # Priority 3: Synthetic RF fallback (16-dim, development only)
        self._rf_model = _build_synthetic_forest()
        self._loaded = True
        self._model_type = "synthetic_rf"
        self._feature_dim = 16
        logger.info("ensemble_synthetic_rf_fallback",
                     n_classes=len(ATTACK_CLASSES),
                     msg="Using synthetic 16-dim RF — run training_pipeline.py for real models")

    def reload_model(self, model_dir: str | None = None) -> None:
        """Hot-swap model artifacts without container restart.

        Called by ModelRetrainer after successful retraining passes F1
        safety check. Re-runs load_models() to pick up new artifacts.
        """
        logger.info("ensemble_hot_reload_starting", current_type=self._model_type)
        old_type = self._model_type
        self.load_models(model_dir)
        logger.info("ensemble_hot_reload_complete",
                     old_type=old_type,
                     new_type=self._model_type)

    async def score(self, features: list[float]) -> dict:
        """Score a feature vector.

        Returns:
            dict with keys:
                - score: float (0-1 composite anomaly probability)
                - label: str (predicted attack class)
                - probabilities: dict[str, float] (per-class)
                - shap_values: dict[str, float] (top contributing features)
                - model_type: str (which model produced the score)
        """
        if not self._loaded:
            return self._stub_score(features)

        if self._model_type == "xgboost":
            return self._xgb_score(features)
        elif self._model_type in ("trained_rf", "synthetic_rf"):
            return self._rf_score(features)
        else:
            return self._stub_score(features)

    def _xgb_score(self, features: list[float]) -> dict:
        """Score using real XGBoost model on 76-dim features."""
        import xgboost as xgb

        padded = (features[:76] + [0.0] * 76)[:76]
        X = np.array([padded], dtype=np.float32)

        # Apply scaler if available
        if self._scaler is not None:
            X = self._scaler.transform(X)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        dmat = xgb.DMatrix(X)
        probas = self._xgb_model.predict(dmat)[0]
        pred_idx = int(np.argmax(probas))
        pred_label = ATTACK_CLASSES[pred_idx]

        benign_prob = float(probas[0])
        composite_score = float(np.clip(1.0 - benign_prob, 0.0, 1.0))

        prob_dict = {cls: float(probas[i]) for i, cls in enumerate(ATTACK_CLASSES)}

        # XGBoost feature importance
        feat_importance = self._get_xgb_importance(X[0])

        return {
            "score": round(composite_score, 4),
            "label": pred_label,
            "probabilities": prob_dict,
            "shap_values": feat_importance,
            "model_type": "xgboost",
        }

    def _get_xgb_importance(self, x: np.ndarray) -> dict:
        """Extract top feature contributions for explainability."""
        importance = {}
        try:
            raw_importance = self._xgb_model.get_score(importance_type="gain")
            top_features = sorted(raw_importance.items(), key=lambda kv: kv[1], reverse=True)[:5]
            for feat_name, gain in top_features:
                # Convert f0, f1, etc. to human-readable block names
                idx = int(feat_name.replace("f", ""))
                block = "unknown"
                for bname, indices in FEATURE_BLOCKS.items():
                    if idx in indices:
                        block = bname
                        break
                importance[f"{block}[{idx}]"] = round(float(gain * abs(x[idx])), 4)
        except Exception:
            pass
        return importance

    def _rf_score(self, features: list[float]) -> dict:
        """Score using RandomForest — works for both trained (76-dim) and synthetic (16-dim)."""
        dim = self._feature_dim
        padded = (features[:dim] + [0.0] * dim)[:dim]
        X = np.array([padded])

        # Apply scaler for trained RF (76-dim)
        if self._model_type == "trained_rf" and self._scaler is not None:
            X = self._scaler.transform(X)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

        probas = self._rf_model.predict_proba(X)[0]
        pred_idx = int(np.argmax(probas))
        pred_label = ATTACK_CLASSES[pred_idx]

        benign_prob = probas[0] if len(probas) > 0 else 0.5
        composite_score = float(np.clip(1.0 - benign_prob, 0.0, 1.0))

        prob_dict = {}
        for i, cls in enumerate(ATTACK_CLASSES):
            prob_dict[cls] = float(probas[i]) if i < len(probas) else 0.0

        # Feature importance
        importances = self._rf_model.feature_importances_
        feat_importance = {}
        top_k = min(5, len(importances))
        top_indices = np.argsort(importances)[-top_k:][::-1]
        for idx in top_indices:
            if self._model_type == "synthetic_rf" and idx < len(FEATURE_NAMES_16):
                feat_importance[FEATURE_NAMES_16[idx]] = round(float(importances[idx] * padded[idx]), 4)
            else:
                block = "unknown"
                for bname, indices in FEATURE_BLOCKS.items():
                    if idx in indices:
                        block = bname
                        break
                feat_importance[f"{block}[{idx}]"] = round(float(importances[idx] * abs(padded[idx])), 4)

        return {
            "score": round(composite_score, 4),
            "label": pred_label,
            "probabilities": prob_dict,
            "shap_values": feat_importance,
            "model_type": self._model_type,
        }

    def _stub_score(self, features: list[float]) -> dict:
        """Deterministic stub if nothing has loaded."""
        raw_signal = min(sum(features[:16]) / 100000.0, 1.0)
        return {
            "score": raw_signal,
            "label": "benign" if raw_signal < 0.5 else "port_scan",
            "probabilities": {cls: 0.0 for cls in ATTACK_CLASSES},
            "shap_values": {},
            "model_type": "stub",
        }

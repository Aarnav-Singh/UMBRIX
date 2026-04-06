"""Model Retrainer — closes the Agent Lightning feedback loop.

Periodically retrains XGBoost/RF models using analyst-verified verdicts
stored in the VerdictBuffer table. Implements safety checks (F1
comparison) and hot-swap reload via EnsembleClassifier.reload_model().
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any

import numpy as np


logger = logging.getLogger(__name__)

_MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "models")


class ModelRetrainer:
    """Manages the verdict-driven model retraining cycle.

    Architecture:
        1. Analyst submits verdict → VerdictBuffer row created (by findings.py)
        2. APScheduler fires daily at 03:00 UTC
        3. If VerdictBuffer has >= 100 new records → retrain_from_verdicts()
        4. Compare new model F1 vs current; only swap if regression < 0.05
        5. EnsembleClassifier.reload_model() hot-swaps without restart
    """

    def __init__(self, postgres: Any, ensemble: Any) -> None:
        self._postgres = postgres
        self._ensemble = ensemble

    async def maybe_retrain(self, tenant_id: str = "default") -> dict[str, Any]:
        """Check buffer size and retrain if threshold met."""
        buffer_count = await self._postgres.count_verdict_buffer(tenant_id)

        if buffer_count < 100:
            logger.info(
                "retraining_skipped",
                extra={"buffer_count": buffer_count, "threshold": 100},
            )
            return {"retrained": False, "buffer_count": buffer_count, "reason": "below_threshold"}

        return await self.retrain_from_verdicts(tenant_id)

    async def retrain_from_verdicts(self, tenant_id: str = "default") -> dict[str, Any]:
        """Execute the full retrain cycle.

        Steps:
            1. Load verdict_buffer features + labels from PostgreSQL
            2. Load existing model artifacts
            3. Incremental fit (XGBoost) / full retrain (RF)
            4. Evaluate on hold-out slice (last 20%)
            5. If new F1 >= old F1 - 0.05: save + reload
            6. Record version in model_versions table
        """
        start = time.perf_counter()

        # 1. Load training data from buffer
        verdicts = await self._postgres.get_verdict_buffer(tenant_id, limit=10000)
        if not verdicts:
            return {"retrained": False, "reason": "empty_buffer"}

        features_list = []
        labels = []
        for v in verdicts:
            try:
                feats = json.loads(v["features_json"]) if isinstance(v["features_json"], str) else v["features_json"]
                features_list.append(feats)
                labels.append(1 if v["label"] == "true_positive" else 0)
            except (json.JSONDecodeError, KeyError):
                continue

        if len(features_list) < 50:
            return {"retrained": False, "reason": "insufficient_valid_data"}

        X = np.array(features_list, dtype=np.float32)
        y = np.array(labels, dtype=np.int32)

        # 2. Train/test split (last 20% as holdout)
        split_idx = int(len(X) * 0.8)
        X_train, X_test = X[:split_idx], X[split_idx:]
        y_train, y_test = y[:split_idx], y[split_idx:]

        # 3. Get current model F1 on holdout
        old_f1 = await self._evaluate_current_model(X_test, y_test)

        # 4. Retrain
        new_xgb_path = os.path.join(_MODELS_DIR, "ensemble_xgb.json")
        new_rf_path = os.path.join(_MODELS_DIR, "ensemble_rf.pkl")
        new_f1_xgb = None
        new_f1_rf = None

        # XGBoost incremental training
        try:
            import xgboost as xgb
            existing_model_path = os.path.join(_MODELS_DIR, "ensemble_xgb.json")
            dtrain = xgb.DMatrix(X_train, label=y_train)
            dtest = xgb.DMatrix(X_test, label=y_test)

            params = {
                "objective": "binary:logistic",
                "eval_metric": "logloss",
                "max_depth": 6,
                "eta": 0.1,
                "verbosity": 0,
            }

            existing_model = None
            if os.path.exists(existing_model_path):
                existing_model = xgb.Booster()
                existing_model.load_model(existing_model_path)

            bst = xgb.train(
                params,
                dtrain,
                num_boost_round=50,
                xgb_model=existing_model,
                evals=[(dtest, "holdout")],
                verbose_eval=False,
            )

            # Evaluate
            preds = (bst.predict(dtest) > 0.5).astype(int)
            from sklearn.metrics import f1_score
            new_f1_xgb = f1_score(y_test, preds, average="weighted", zero_division=0)

            # Save if acceptable
            if new_f1_xgb >= old_f1 - 0.05:
                bst.save_model(new_xgb_path)
                logger.info("xgb_retrained", extra={"f1": new_f1_xgb})
        except ImportError:
            logger.warning("xgboost_not_available")
        except Exception as exc:
            logger.error("xgb_retrain_failed", extra={"error": str(exc)})

        # RandomForest full retrain
        try:
            from sklearn.ensemble import RandomForestClassifier
            import joblib
            rf = RandomForestClassifier(
                n_estimators=200,
                max_depth=12,
                random_state=42,
                class_weight="balanced",
                n_jobs=-1,
            )
            rf.fit(X_train, y_train)
            rf_preds = rf.predict(X_test)
            from sklearn.metrics import f1_score
            new_f1_rf = f1_score(y_test, rf_preds, average="weighted", zero_division=0)

            if new_f1_rf >= old_f1 - 0.05:
                joblib.dump(rf, new_rf_path)
                logger.info("rf_retrained", extra={"f1": new_f1_rf})
        except Exception as exc:
            logger.error("rf_retrain_failed", extra={"error": str(exc)})

        # 5. Hot-swap reload
        best_f1 = max(filter(None, [new_f1_xgb, new_f1_rf, 0.0]))
        if best_f1 >= old_f1 - 0.05:
            self._ensemble.reload_model()
            logger.info("model_hot_swapped", extra={"new_f1": best_f1, "old_f1": old_f1})
        else:
            logger.warning(
                "model_swap_rejected",
                extra={"new_f1": best_f1, "old_f1": old_f1},
            )

        # 6. Record version
        elapsed = time.perf_counter() - start
        version_record = {
            "tenant_id": tenant_id,
            "version": datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
            "xgb_f1": new_f1_xgb,
            "rf_f1": new_f1_rf,
            "previous_f1": old_f1,
            "buffer_size": len(verdicts),
            "training_time_seconds": round(elapsed, 2),
        }
        await self._postgres.save_model_version(version_record)

        return {
            "retrained": True,
            "xgb_f1": new_f1_xgb,
            "rf_f1": new_f1_rf,
            "previous_f1": old_f1,
            "buffer_size": len(verdicts),
            "swapped": best_f1 >= old_f1 - 0.05,
        }

    async def _evaluate_current_model(self, X: np.ndarray, y: np.ndarray) -> float:
        """Evaluate the current ensemble model on a dataset, return F1."""
        try:
            predictions = []
            for row in X:
                result = await self._ensemble.score(row.tolist())
                pred = 0 if result.get("top_class", "benign") == "benign" else 1
                predictions.append(pred)

            from sklearn.metrics import f1_score
            return f1_score(y, predictions, average="weighted", zero_division=0)
        except Exception:
            return 0.0  # No current model available


def schedule_retraining(postgres: Any, ensemble: Any) -> None:
    """Register the daily retraining job with APScheduler.

    Call this during ASGI lifespan startup.
    """
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from apscheduler.triggers.cron import CronTrigger

        retrainer = ModelRetrainer(postgres=postgres, ensemble=ensemble)
        scheduler = AsyncIOScheduler()
        scheduler.add_job(
            retrainer.maybe_retrain,
            trigger=CronTrigger(hour=3, minute=0),  # 03:00 UTC daily
            id="model_retraining",
            name="Daily ML model retraining from analyst verdicts",
            replace_existing=True,
        )
        scheduler.start()
        logger.info("model_retraining_scheduled", extra={"cron": "03:00 UTC daily"})
    except ImportError:
        logger.warning("apscheduler_not_available")

"""Meta-Learner: Fusion of 5 ML stream scores with persistent weights.

Takes all five stream scores + 9 contextual features and produces
a single composite detection score. Weights update continuously
via analyst TP/FP verdicts and are persisted to PostgreSQL
to survive service restarts.

Phase 22B: Weights now persist to the `meta_learner_weights` table
in PostgreSQL, keyed by tenant_id. Falls back to in-memory if
no database is available.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional, Any

import numpy as np

import structlog

logger = structlog.get_logger(__name__)

# Default weights before any analyst feedback
DEFAULT_WEIGHTS = [0.25, 0.20, 0.15, 0.20, 0.20]


class MetaLearner:
    """Score fusion with persistent weight learning.

    Uses a weighted average of 5 ML stream scores
    with context-aware adjustments. Weights are updated via analyst
    verdicts (TP/FP) and persisted to PostgreSQL.
    """

    def __init__(self, postgres: Any = None) -> None:
        self._model = None
        self._loaded = False
        self._weights = DEFAULT_WEIGHTS.copy()
        self._postgres = postgres  # PostgresRepository or None
        self._verdicts_processed = 0
        self._tenant_id = "default"

    def load_model(self, path: Optional[str] = None) -> None:
        if path:
            try:
                import lightgbm as lgb
                self._model = lgb.Booster(model_file=path)
                self._loaded = True
                logger.info("meta_learner_loaded", path=path)
            except Exception as exc:
                logger.warning("meta_learner_load_failed", error=str(exc))
        else:
            logger.info("meta_learner_weighted_average_mode")

    async def load_persisted_weights(self, tenant_id: str = "default") -> None:
        """Load weights from PostgreSQL at startup.

        Called during pipeline initialization. If no persisted weights
        exist, uses DEFAULT_WEIGHTS.
        """
        self._tenant_id = tenant_id
        if not self._postgres:
            logger.info("meta_learner_no_postgres", msg="No persistence backend, using defaults")
            return

        try:
            weights = await self._postgres.load_meta_learner_weights(tenant_id)
            if weights:
                self._weights = weights
                logger.info("meta_learner_weights_restored",
                            tenant_id=tenant_id,
                            weights=self._weights)
            else:
                logger.info("meta_learner_no_persisted_weights",
                            tenant_id=tenant_id,
                            msg="Using defaults, will persist on first verdict")
        except Exception as exc:
            logger.warning("meta_learner_restore_failed", error=str(exc))

    async def score(
        self,
        stream_scores: list[float],
        context_features: Optional[list[float]] = None,
    ) -> float:
        """Fuse 5 stream scores into a single composite score.

        Args:
            stream_scores: [ensemble, vae, hst, temporal, adversarial]
            context_features: [hour, asset_crit, campaign_stage, ...]
        """
        assert len(stream_scores) == 5, f"Expected 5 stream scores, got {len(stream_scores)}"

        if self._loaded and self._model:
            features = stream_scores + (context_features or [0.0] * 9)
            arr = np.array([features])
            return float(self._model.predict(arr)[0])

        # Weighted average with context adjustment
        base_score = sum(s * w for s, w in zip(stream_scores, self._weights))

        # Apply context multiplier if available
        if context_features and len(context_features) >= 2:
            hour = context_features[0] if context_features[0] >= 0 else datetime.utcnow().hour
            asset_crit = context_features[1] if len(context_features) > 1 else 0.5

            # Off-hours events are more suspicious (22:00-06:00)
            hour_boost = 0.05 if (hour >= 22 or hour <= 6) else 0.0

            # High-value assets get a score boost
            asset_boost = 0.03 * (asset_crit - 0.5) if asset_crit > 0.5 else 0.0

            base_score = min(base_score + hour_boost + asset_boost, 1.0)

        # Apply non-linear amplification for signals above threshold
        if base_score > 0.3:
            base_score = base_score ** 0.85  # Slight amplification

        return float(np.clip(base_score, 0.0, 1.0))

    def update_weights(self, verdict: str, stream_scores: list[float]) -> None:
        """Adjust weights based on analyst feedback.

        True positive: increase weight of streams that scored high.
        False positive: decrease weight of streams that scored high.

        Weights are persisted asynchronously after update.
        """
        learning_rate = 0.01

        if verdict == "true_positive":
            for i, score in enumerate(stream_scores):
                if score > 0.5:
                    self._weights[i] = min(self._weights[i] + learning_rate, 0.5)
        elif verdict == "false_positive":
            for i, score in enumerate(stream_scores):
                if score > 0.5:
                    self._weights[i] = max(self._weights[i] - learning_rate, 0.05)

        # Re-normalize to sum to 1
        total = sum(self._weights)
        self._weights = [w / total for w in self._weights]
        self._verdicts_processed += 1

        logger.info(
            "meta_learner_weights_updated",
            verdict=verdict,
            weights=self._weights,
            verdicts_processed=self._verdicts_processed,
        )

    async def persist_weights(self, tenant_id: Optional[str] = None) -> None:
        """Persist current weights to PostgreSQL.

        Called after update_weights() when a database connection is available.
        Separated from update_weights() to keep the sync interface backward
        compatible while enabling async persistence.
        """
        tid = tenant_id or self._tenant_id
        if not self._postgres:
            return

        try:
            await self._postgres.save_meta_learner_weights(
                weights=self._weights,
                verdicts_processed=self._verdicts_processed,
                tenant_id=tid,
            )
        except Exception as exc:
            logger.warning("meta_learner_persist_failed",
                           error=str(exc),
                           msg="Weights are safe in-memory, will retry on next verdict")

    @property
    def current_weights(self) -> list[float]:
        return self._weights.copy()

    @property
    def verdicts_processed(self) -> int:
        return self._verdicts_processed

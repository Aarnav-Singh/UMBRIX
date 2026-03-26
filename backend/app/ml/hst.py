"""Stream 3: Half-Space Trees -- Adaptive Real-Time Anomaly.

Uses the River library's incremental HST implementation.
Updates its internal model on every single event in real time
without retraining, downtime, or deployment.

Phase 22C: Added seed_from_aggregate_stats() to solve cold-start
by pre-populating the model from the first window of training data.
"""
from __future__ import annotations

from typing import Optional

import structlog

logger = structlog.get_logger(__name__)

# Minimum events before HST scoring is considered reliable
COLD_START_THRESHOLD = 500


class HSTAnomalyDetector:
    """Online Half-Space Trees anomaly detector with cold-start seeding."""

    def __init__(self, n_trees: int = 25, height: int = 8, window_size: int = 1000) -> None:
        self._n_trees = n_trees
        self._height = height
        self._window_size = window_size
        self._model = None
        self._event_count = 0
        self._seeded = False

        try:
            from river import anomaly
            self._model = anomaly.HalfSpaceTrees(
                n_trees=n_trees,
                height=height,
                window_size=window_size,
                seed=42,
            )
            logger.info("hst_initialized", n_trees=n_trees, height=height, window_size=window_size)
        except ImportError:
            logger.warning("hst_river_not_available",
                           msg="River library not installed. HST will return 0.0 for all events.")

    def seed_from_aggregate_stats(
        self,
        training_data: Optional[list[list[float]]] = None,
        data_path: Optional[str] = None,
    ) -> int:
        """Pre-populate HST from aggregate data to solve cold-start.

        Feeds the model with benign baseline data so it can produce
        reliable anomaly scores from the very first production event.

        Args:
            training_data: List of 76-dim feature vectors (benign only).
            data_path: Path to CSV file with training data.

        Returns:
            Number of events fed to the model.
        """
        if self._model is None:
            logger.warning("hst_seed_skipped", msg="River not available")
            return 0

        events_fed = 0

        # Option 1: Direct feature vectors
        if training_data:
            for features in training_data:
                feature_dict = {f"f{i}": v for i, v in enumerate(features)}
                self._model.learn_one(feature_dict)
                events_fed += 1

        # Option 2: Load from CSV
        elif data_path:
            try:
                import numpy as np
                import os

                if not os.path.exists(data_path):
                    logger.warning("hst_seed_file_not_found", path=data_path)
                    return 0

                # Load and filter benign-only data
                data = np.load(data_path) if data_path.endswith('.npy') else None
                if data is None:
                    import pandas as pd
                    df = pd.read_csv(data_path)
                    df.columns = df.columns.str.strip()

                    # Filter benign if Label column exists
                    if "Label" in df.columns:
                        df = df[df["Label"].isin(["benign", "BENIGN"])]

                    # Use numeric columns as features
                    numeric_cols = df.select_dtypes(include=["number"]).columns
                    data = df[numeric_cols].fillna(0).values

                # Feed first window_size samples (cap to prevent slow startup)
                cap = min(len(data), self._window_size * 2)
                for row in data[:cap]:
                    features = row.tolist()
                    feature_dict = {f"f{i}": v for i, v in enumerate(features)}
                    self._model.learn_one(feature_dict)
                    events_fed += 1

            except Exception as exc:
                logger.warning("hst_seed_from_file_failed", error=str(exc))

        # Option 3: Generate synthetic benign baseline
        if events_fed == 0:
            events_fed = self._seed_synthetic_baseline()

        self._event_count += events_fed
        self._seeded = True
        logger.info("hst_baseline_seeded",
                     events_fed=events_fed,
                     total_events=self._event_count)
        return events_fed

    def _seed_synthetic_baseline(self) -> int:
        """Generate a minimal synthetic benign baseline for cold-start.

        Used when no training data is available. Creates feature vectors
        with distributions approximating normal network traffic.
        """
        import numpy as np

        if self._model is None:
            return 0

        rng = np.random.RandomState(42)
        n_seed = self._window_size  # Fill one full window

        for _ in range(n_seed):
            # Approximate benign traffic pattern across 76 dims
            features = np.zeros(76)
            # Network features (0-15): normal traffic
            features[0] = rng.choice([80, 443, 8080, 8443])  # src_port
            features[1] = rng.choice([80, 443, 53, 22])       # dst_port
            features[2] = rng.exponential(500)                 # bytes_in
            features[3] = rng.exponential(2000)                # bytes_out
            features[4] = rng.poisson(5) + 1                   # packets_in
            features[5] = rng.poisson(5) + 1                   # packets_out
            # Add small noise to remaining features
            features[16:32] = rng.uniform(0, 0.3, 16)  # entity behavioral
            features[32:48] = rng.exponential(0.1, 16)  # temporal

            feature_dict = {f"f{i}": float(v) for i, v in enumerate(features)}
            self._model.learn_one(feature_dict)

        return n_seed

    async def score(self, features: list[float]) -> float:
        """Score and update the model in one pass.

        River's HST returns a score in [0, 1] where 1 = most anomalous.
        The model updates incrementally on every call.

        During cold-start (< COLD_START_THRESHOLD events without seeding),
        scores are dampened to avoid false positives.
        """
        if self._model is None:
            return 0.0

        feature_dict = {f"f{i}": v for i, v in enumerate(features)}

        # Score THEN learn (evaluate before adapting)
        raw_score = self._model.score_one(feature_dict)
        self._model.learn_one(feature_dict)
        self._event_count += 1

        # Dampen scores during cold-start if not seeded
        if not self._seeded and self._event_count < COLD_START_THRESHOLD:
            dampening = self._event_count / COLD_START_THRESHOLD
            raw_score *= dampening

        if self._event_count % 10000 == 0:
            logger.info("hst_checkpoint",
                        events_processed=self._event_count,
                        seeded=self._seeded)

        return raw_score

    @property
    def events_processed(self) -> int:
        return self._event_count

    @property
    def is_seeded(self) -> bool:
        return self._seeded

import pytest
from unittest.mock import AsyncMock, MagicMock

from app.schemas.canonical_event import CanonicalEvent, Entity, NetworkInfo
from app.services.pipeline import PipelineService

@pytest.fixture
def mock_event():
    return CanonicalEvent(
        event_id="test-evt-123",
        timestamp="2026-03-01T12:00:00Z",
        source_type="syslog",
        message="Failed password for root from 192.168.1.100 port 22 ssh2",
        source_entity=Entity(identifier="host-A", entity_type="host", asset_criticality=0.8),
        network=NetworkInfo(src_ip="192.168.1.100", dst_ip="10.0.0.1", dst_port=22),
    )

@pytest.fixture
def pipeline_deps():
    return {
        "clickhouse": MagicMock(insert_event=AsyncMock()),
        "redis": MagicMock(
            get_entity_state=AsyncMock(),
            atomic_update_entity_state=AsyncMock(),
            get_all_campaigns=AsyncMock(),
        ),
        "qdrant": MagicMock(
            upsert_behavioral_dna=AsyncMock(),
            upsert_ioc=AsyncMock(),
            upsert_campaign=AsyncMock(),
        ),
        "postgres": MagicMock(),
        "broadcaster": MagicMock(broadcast=AsyncMock()),
        "feed_manager": MagicMock(
            check_ioc=AsyncMock(return_value=None),
            update_feed_status=AsyncMock()
        ),
    }

@pytest.mark.asyncio
async def test_pipeline_15_step_execution(mock_event, pipeline_deps):
    """
    Validates that a CanonicalEvent successfully passes through all 15 steps
    of the PipelineService without crashing, and appropriate sub-services are called.
    """
    # Arrange: Mock ML ensemble outcomes
    svc = PipelineService(
        clickhouse=pipeline_deps["clickhouse"],
        redis=pipeline_deps["redis"],
        qdrant=pipeline_deps["qdrant"],
        postgres=pipeline_deps["postgres"],
        broadcaster=pipeline_deps["broadcaster"],
        feed_manager=pipeline_deps["feed_manager"],
        narrative_mode="template"
    )

    # Mock ML scoring
    svc._ensemble.score = AsyncMock(return_value={"score": 0.8, "label": "malicious", "shap_values": {}})
    svc._vae.score = AsyncMock(return_value=0.7)
    svc._hst.score = AsyncMock(return_value=0.6)
    svc._temporal.score = AsyncMock(return_value=0.5)
    svc._adversarial.score = AsyncMock(return_value={"composite": 0.4, "timing_cov": 0.1})
    svc._meta.score = AsyncMock(return_value=0.9)

    # Mock Agentic RAG
    svc._agentic_rag.retrieve_context = AsyncMock(return_value={"rag": "context"})
    
    # Mock Redis entity state
    pipeline_deps["redis"].get_entity_state = AsyncMock(return_value={"event_count": 5})
    # Mock Alerting 
    svc._alerting.dispatch = AsyncMock()
    # Mock Correlation engine inside PipelineService
    svc._correlate_campaign = AsyncMock()

    # Act
    processed_event = await svc.process(mock_event)

    # Assert ML Scores attached (Steps 1a-1f)
    assert processed_event.ml_scores is not None
    assert processed_event.ml_scores.ensemble_score == 0.8
    assert processed_event.ml_scores.meta_score == 0.9

    # Assert Qdrant Upserts (Phase 2 Vectors)
    pipeline_deps["qdrant"].upsert_behavioral_dna.assert_awaited_once()

    # Assert Redis State Update
    pipeline_deps["redis"].atomic_update_entity_state.assert_awaited_once_with(
        "default",
        "host-A",
        event_ts=mock_event.timestamp.timestamp(),
        dst_ip="10.0.0.1",
        dst_port=22,
        campaign_id=None
    )

    # Assert Narrative Generated
    assert isinstance(processed_event.message, str)
    assert len(processed_event.message) > 0

    # Assert Delivery (Steps 11 & 12)
    pipeline_deps["clickhouse"].insert_event.assert_awaited_once_with(processed_event)
    pipeline_deps["broadcaster"].broadcast.assert_awaited_once()
    
    # Check Pipeline metrics updated
    assert processed_event.metadata.pipeline_duration_ms > 0
    assert svc.events_processed == 1

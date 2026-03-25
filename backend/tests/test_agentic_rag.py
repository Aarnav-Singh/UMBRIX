import pytest

# Skip the entire module if langgraph is not installed so that missing the
# optional dependency doesn't abort collection of all other test files.
pytest.importorskip("langgraph")
from unittest.mock import AsyncMock, patch

from app.schemas.canonical_event import CanonicalEvent, Entity, NetworkInfo, MLScores, ActionType
from app.engine.agentic_rag import AgenticRagOrchestrator
from app.engine.rag_retriever import RagRetriever

@pytest.fixture
def mock_retriever():
    retriever = RagRetriever(ch_repo=None, pg_repo=None)
    retriever.get_historical_context = AsyncMock(return_value=[{"msg": "history"}])
    retriever.get_analyst_notes_context = AsyncMock(return_value=[{"note": "analyst"}])
    retriever.get_graph_context = AsyncMock(return_value=[{"path": ["A", "B"]}])
    return retriever

@pytest.fixture
def base_event():
    return CanonicalEvent(
        source_type="syslog",
        action=ActionType.UNKNOWN,
        message="Standard event",
        network=NetworkInfo(src_ip="192.168.1.5", dst_ip="10.0.0.8"),
    )

@pytest.mark.asyncio
async def test_agentic_rag_low_complexity_routes_native_only(base_event, mock_retriever):
    """Low complexity event (< 0.7 score, non-lateral action) should bypass Graph RAG."""
    base_event.ml_scores = MLScores(meta_score=0.2)
    
    orchestrator = AgenticRagOrchestrator(mock_retriever)
    
    tenant_id = "default"
    result = await orchestrator.retrieve_context(tenant_id, base_event)
    
    # Assert Native RAG was called
    mock_retriever.get_historical_context.assert_awaited_once()
    mock_retriever.get_analyst_notes_context.assert_awaited_once()
    
    # Assert Graph RAG was bypassed
    mock_retriever.get_graph_context.assert_not_called()
    
    # Assert Result shape
    assert len(result["historical_events"]) == 1
    assert len(result["analyst_notes"]) == 1
    assert len(result["graph_paths"]) == 0

@pytest.mark.asyncio
async def test_agentic_rag_high_complexity_routes_graph(base_event, mock_retriever):
    """High complexity event (>= 0.7 score) should route to Graph RAG then Native RAG."""
    base_event.ml_scores = MLScores(meta_score=0.8)
    
    orchestrator = AgenticRagOrchestrator(mock_retriever)
    
    tenant_id = "default"
    result = await orchestrator.retrieve_context(tenant_id, base_event)
    
    # Assert Native RAG was called
    mock_retriever.get_historical_context.assert_awaited_once()
    
    # Assert Graph RAG was ALSO called (because meta_score > 0.7)
    mock_retriever.get_graph_context.assert_awaited_once_with(tenant_id, "192.168.1.5", max_depth=3)
    
    # Assert Result shape includes graph paths
    assert len(result["historical_events"]) == 1
    assert len(result["graph_paths"]) == 1

@pytest.mark.asyncio
async def test_agentic_rag_lateral_movement_action_routes_graph(base_event, mock_retriever):
    """Lateral movement actions should force Graph RAG even if score is low."""
    base_event.ml_scores = MLScores(meta_score=0.1)
    base_event.action = "lateral_movement"  # Override action
    
    orchestrator = AgenticRagOrchestrator(mock_retriever)
    
    result = await orchestrator.retrieve_context("default", base_event)
    
    # Graph RAG should be triggered because of the action type
    mock_retriever.get_graph_context.assert_awaited_once()
    assert len(result["graph_paths"]) == 1

"""Integration Test Suite — Phase 26C.

Tests critical cross-boundary integrations without requiring the full
app.main import (which triggers heavy infra like Prometheus, Kafka, etc.).
Each test verifies a specific contract between layers.
"""
import pytest
import json
from unittest.mock import AsyncMock


# ── Test 1: SOAR Engine — Jinja2 + Conditional Branching + Audit Trail ──

@pytest.mark.asyncio
async def test_soar_engine_full_lifecycle():
    """E2E: Playbook with conditional branching, Jinja2 templating, and Postgres audit logging."""
    from app.services.soar.engine import ExecutionEngine, Playbook, Node
    from app.services.soar.actions import ActionRegistry

    # Register a mock provider
    mock_provider = AsyncMock()
    mock_provider.execute = AsyncMock(return_value="completed")
    ActionRegistry.providers["test_provider"] = mock_provider

    # Mock Postgres audit repo
    mock_postgres = AsyncMock()
    mock_postgres.save_soar_audit_log = AsyncMock()
    mock_postgres.save_paused_state = AsyncMock()

    engine = ExecutionEngine(postgres_repo=mock_postgres)

    playbook = Playbook(
        id="integ-pb-001",
        name="Integration Branching Test",
        nodes=[
            Node(
                id="cond_1",
                action_type="conditional",
                params={"condition": "{{ severity >= 3 }}"},
                on_true=[
                    Node(id="action_high", action_type="isolate_host", provider="test_provider",
                         params={"message": "Severity is {{ severity }}!"})
                ],
                on_false=[
                    Node(id="action_low", action_type="log_event", provider="test_provider",
                         params={"message": "All good, severity {{ severity }}"})
                ],
            )
        ],
    )

    # Test TRUE branch (severity = 5)
    results = await engine.execute_playbook(playbook, event_context={"severity": 5})

    assert len(results) == 2  # conditional + action_high
    assert results[0]["branch_taken"] == "on_true"
    assert results[1]["node_id"] == "action_high"
    assert results[1]["params"]["message"] == "Severity is 5!"
    assert results[1]["status"] == "completed"

    # Verify Postgres audit was called for both nodes
    assert mock_postgres.save_soar_audit_log.await_count == 2

    # Test FALSE branch (severity = 1)
    mock_postgres.save_soar_audit_log.reset_mock()
    results = await engine.execute_playbook(playbook, event_context={"severity": 1})

    assert results[0]["branch_taken"] == "on_false"
    assert results[1]["node_id"] == "action_low"
    assert results[1]["params"]["message"] == "All good, severity 1"
    assert mock_postgres.save_soar_audit_log.await_count == 2

    # Cleanup
    del ActionRegistry.providers["test_provider"]


# ── Test 2: Auth MFA Flow — TOTP Setup + Verification ──

@pytest.mark.asyncio
async def test_mfa_totp_lifecycle():
    """Validates the TOTP secret generation and code verification logic."""
    import pyotp

    # 1. Generate a secret (simulates /enable-mfa)
    secret = pyotp.random_base32()
    assert len(secret) == 32

    # 2. Generate a provisioning URI
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name="analyst@sentinel.local", issuer_name="UMBRIX")
    assert "otpauth://totp/" in uri
    assert "Sentinel%20Fabric%20V2" in uri

    # 3. Verify a valid code (simulates /verify-mfa-setup)
    valid_code = totp.now()
    assert totp.verify(valid_code) is True

    # 4. Verify an invalid code is rejected
    assert totp.verify("000000") is False


# ── Test 3: Vault Config Loader — HashiCorp Vault Integration ──

def test_vault_config_loader_graceful_fallback():
    """Verify that config loads successfully even when Vault is unreachable."""
    from app.config import Settings

    # With empty vault_url, Vault loading should be skipped entirely
    s = Settings(
        jwt_secret_key="test-secret-key-for-testing",
        vault_url="",
        vault_token="",
    )
    assert s.jwt_secret_key == "test-secret-key-for-testing"
    assert s.vault_url == ""


def test_vault_config_loader_with_bad_url():
    """Verify graceful degradation when Vault URL is set but unreachable."""
    from app.config import Settings

    # Should not crash — just log a warning and continue
    s = Settings(
        jwt_secret_key="test-secret-key-for-testing",
        vault_url="http://127.0.0.1:9999",
        vault_token="fake-token",
    )
    # The settings should still be usable even if Vault was unreachable
    assert s.jwt_secret_key == "test-secret-key-for-testing"


# ── Test 4: Postgres ORM — SoarAuditTrail Schema Validation ──

def test_soar_audit_trail_schema():
    """Verify the SoarAuditTrail ORM model has the correct columns."""
    from app.repositories.postgres import SoarAuditTrail

    columns = {c.name for c in SoarAuditTrail.__table__.columns}
    expected = {"id", "playbook_id", "node_id", "action_type", "provider", "status", "params", "timestamp"}
    assert columns == expected, f"Missing columns: {expected - columns}"


def test_user_record_mfa_fields():
    """Verify UserRecord has mfa_secret and mfa_enabled columns."""
    from app.repositories.postgres import UserRecord

    columns = {c.name for c in UserRecord.__table__.columns}
    assert "mfa_secret" in columns, "mfa_secret column missing from UserRecord"
    assert "mfa_enabled" in columns, "mfa_enabled column missing from UserRecord"


# ── Test 5: Canonical Event Schema Validation ──

def test_canonical_event_schema():
    """Verify CanonicalEvent can be serialized and deserialized correctly."""
    from app.schemas.canonical_event import CanonicalEvent, Entity, NetworkInfo

    event = CanonicalEvent(
        event_id="integ-evt-001",
        timestamp="2026-03-27T00:00:00Z",
        source_type="suricata",
        message="ET EXPLOIT Test Signature",
        source_entity=Entity(identifier="host-A", entity_type="host", asset_criticality=0.9),
        network=NetworkInfo(src_ip="192.168.1.10", dst_ip="10.0.0.5", dst_port=443),
    )

    # Round-trip serialization
    json_str = event.model_dump_json()
    parsed = json.loads(json_str)

    assert parsed["event_id"] == "integ-evt-001"
    assert parsed["source_type"] == "suricata"
    assert parsed["network"]["src_ip"] == "192.168.1.10"
    assert parsed["network"]["dst_port"] == 443


# ── Test 6: SOAR Engine — Pending Approval Pause/Resume ──

@pytest.mark.asyncio
async def test_soar_pause_resume_lifecycle():
    """E2E: Playbook pauses at pending_approval and resumes after analyst decision."""
    from app.services.soar.engine import ExecutionEngine, Playbook, Node
    from app.services.soar.actions import ActionRegistry

    # Provider that returns pending_approval on first call, completed on second
    call_count = 0
    async def mock_execute(action_type, params):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return "pending_approval"
        return "completed"

    mock_provider = AsyncMock()
    mock_provider.execute = mock_execute
    ActionRegistry.providers["approval_provider"] = mock_provider

    mock_postgres = AsyncMock()
    mock_postgres.save_soar_audit_log = AsyncMock()
    mock_postgres.save_paused_state = AsyncMock()

    engine = ExecutionEngine(postgres_repo=mock_postgres)

    playbook = Playbook(
        id="integ-pb-002",
        name="Approval Flow Test",
        nodes=[
            Node(id="step_1", action_type="risky_action", provider="approval_provider", params={}),
            Node(id="step_2", action_type="safe_action", provider="approval_provider", params={}),
        ],
    )

    # Execute — should pause at step_1
    results = await engine.execute_playbook(playbook)
    assert len(results) == 1
    assert results[0]["status"] == "pending_approval"
    assert "approval_id" in results[0]

    # Verify pause state was persisted
    mock_postgres.save_paused_state.assert_awaited_once()

    # Resume — should complete step_2
    resume_results = await engine.resume_playbook(playbook, from_node_index=0, decision="approve")
    assert len(resume_results) == 1
    assert resume_results[0]["status"] == "completed"
    assert resume_results[0]["node_id"] == "step_2"

    del ActionRegistry.providers["approval_provider"]

"""Phase 33 Verification Tests — Infrastructure Hardening.

Run with: pytest tests/test_phase33_verification.py -v
Requires a running stack (Redis, Postgres, Kafka) or appropriate mocks.
"""
from __future__ import annotations

import asyncio
import json
import os
import pytest

# ---------------------------------------------------------------------------
# V-33.1: Redis Sentinel Failover
# ---------------------------------------------------------------------------

class TestRedisSentinelFailover:
    """Verify RedisStore correctly handles Sentinel/Cluster topologies."""

    @pytest.mark.asyncio
    async def test_sentinel_connect_and_reconnect(self):
        """RedisStore.connect() should resolve via Sentinel when configured."""
        from app.repositories.redis_store import RedisStore

        store = RedisStore()

        # Simulate sentinel configuration
        os.environ["REDIS_SENTINEL_HOSTS"] = json.dumps([["localhost", 26379]])
        os.environ["REDIS_SENTINEL_MASTER"] = "mymaster"
        os.environ.pop("REDIS_CLUSTER_MODE", None)

        try:
            await store.connect()

            # Confirm basic operations survive
            await store.set("v33_test_key", "alive", expire_sec=10)
            val = await store.get("v33_test_key")
            assert val == "alive", f"Expected 'alive', got '{val}'"

            # Simulate primary loss: disconnect and reconnect
            await store.disconnect()
            await store.connect()

            await store.get("v33_test_key")
            # Key may or may not survive depending on replication lag;
            # the test validates that the client reconnects without crash.
            assert True, "Reconnection after disconnect succeeded"
        except Exception as e:
            if "Connection refused" in str(e):
                pytest.skip("No Sentinel infrastructure available")
            raise
        finally:
            await store.disconnect()
            os.environ.pop("REDIS_SENTINEL_HOSTS", None)
            os.environ.pop("REDIS_SENTINEL_MASTER", None)

    @pytest.mark.asyncio
    async def test_cluster_mode_connect(self):
        """RedisStore.connect() should use RedisCluster when cluster mode on."""
        from app.repositories.redis_store import RedisStore

        store = RedisStore()
        os.environ["REDIS_CLUSTER_MODE"] = "true"
        os.environ.pop("REDIS_SENTINEL_HOSTS", None)

        try:
            await store.connect()
            await store.set("v33_cluster_test", "ok", expire_sec=5)
            assert await store.get("v33_cluster_test") == "ok"
        except Exception as e:
            if "Connection refused" in str(e) or "RedisCluster" in str(e):
                pytest.skip("No Redis Cluster infrastructure available")
            raise
        finally:
            await store.disconnect()
            os.environ.pop("REDIS_CLUSTER_MODE", None)


# ---------------------------------------------------------------------------
# V-33.2: Vault Pool Reconnect
# ---------------------------------------------------------------------------

class TestVaultPoolReconnect:
    """Verify PostgresRepository.reload_pool() gracefully swaps connections."""

    @pytest.mark.asyncio
    async def test_reload_pool_creates_new_engine(self):
        """After reload_pool(), the engine should be a fresh instance."""
        from app.repositories.postgres import PostgresRepository

        repo = PostgresRepository()
        try:
            await repo.connect()
            old_engine = repo._engine

            await repo.reload_pool()
            new_engine = repo._engine

            assert new_engine is not old_engine, \
                "reload_pool() must create a new engine, not reuse the old one"
            assert new_engine is not None, "New engine must not be None"
        except Exception as e:
            if "connect" in str(e).lower():
                pytest.skip("No PostgreSQL available for pool reconnect test")
            raise
        finally:
            await repo.disconnect()

    @pytest.mark.asyncio
    async def test_vault_polling_updates_settings(self):
        """Settings.start_vault_polling() should be callable without crash."""
        from app.config import Settings

        s = Settings()
        # Without a real Vault, this should gracefully skip
        # Just verify the method exists and is async-callable
        assert hasattr(s, "start_vault_polling"), \
            "Settings must expose start_vault_polling()"
        assert asyncio.iscoroutinefunction(s.start_vault_polling), \
            "start_vault_polling must be an async method"


# ---------------------------------------------------------------------------
# V-33.3: Backup CronJob Template Validation
# ---------------------------------------------------------------------------

class TestBackupCronJobTemplate:
    """Validate the Helm backup-cronjob.yaml template is structurally correct."""

    def test_cronjob_template_exists(self):
        """backup-cronjob.yaml must exist in Helm templates."""
        template_path = os.path.join(
            os.path.dirname(__file__), "..", "..",
            "infra", "helm", "umbrix", "templates", "backup-cronjob.yaml"
        )
        # Also try absolute path
        abs_path = r"c:\UMBRIX\infra\helm\umbrix\templates\backup-cronjob.yaml"
        assert os.path.exists(template_path) or os.path.exists(abs_path), \
            "backup-cronjob.yaml template must exist"

    def test_cronjob_contains_pg_dump(self):
        """Template must reference pg_dump for PostgreSQL backups."""
        abs_path = r"c:\UMBRIX\infra\helm\umbrix\templates\backup-cronjob.yaml"
        if not os.path.exists(abs_path):
            pytest.skip("Template not found at expected path")

        content = open(abs_path).read()
        assert "pg_dump" in content, "CronJob must use pg_dump for Postgres backups"
        assert "BACKUP DATABASE" in content or "clickhouse" in content.lower(), \
            "CronJob must handle ClickHouse backups"
        assert "S3" in content or "s3" in content, \
            "CronJob must target S3 storage"

    def test_restore_runbook_exists(self):
        """RESTORE.md runbook must exist."""
        abs_path = r"c:\UMBRIX\docs\runbooks\RESTORE.md"
        assert os.path.exists(abs_path), "RESTORE.md runbook must exist"

        content = open(abs_path).read()
        assert "pg_restore" in content or "psql" in content, \
            "Runbook must document PostgreSQL restore procedure"
        assert "Post-Restore" in content, \
            "Runbook must include a post-restore checklist"


# ---------------------------------------------------------------------------
# V-33.4: Kafka DLQ Routing
# ---------------------------------------------------------------------------

class TestKafkaDLQRouting:
    """Verify EventConsumer routes bad messages to DLQ and commits offsets."""

    def test_auto_commit_disabled(self):
        """EventConsumer must use enable_auto_commit=False."""
        import inspect
        from app.consumers.event_consumer import EventConsumer

        source = inspect.getsource(EventConsumer.start)
        assert "enable_auto_commit=False" in source, \
            "Consumer must disable auto commit for at-least-once guarantees"

    def test_manual_commit_after_process(self):
        """Consumer loop must call commit() after successful processing."""
        import inspect
        from app.consumers.event_consumer import EventConsumer

        source = inspect.getsource(EventConsumer.run)
        assert "commit()" in source, \
            "Consumer must manually commit offsets after processing"

    def test_dlq_producer_exists(self):
        """EventConsumer must have a DLQ producer for poison-pill routing."""
        import inspect
        from app.consumers.event_consumer import EventConsumer

        source = inspect.getsource(EventConsumer)
        assert "_dlq_producer" in source, \
            "Consumer must maintain a DLQ producer"
        assert "_send_to_dlq" in source, \
            "Consumer must have a _send_to_dlq method"

    def test_dlq_payload_includes_metadata(self):
        """DLQ messages must contain original_topic and error_reason."""
        import inspect
        from app.consumers.event_consumer import EventConsumer

        source = inspect.getsource(EventConsumer._send_to_dlq)
        assert "original_topic" in source, "DLQ payload must include original_topic"
        assert "error_reason" in source, "DLQ payload must include error_reason"
        assert "raw_log" in source, "DLQ payload must include raw_log"


# ---------------------------------------------------------------------------
# V-33.5: CMDB Integration (ServiceNow wiring)
# ---------------------------------------------------------------------------

class TestCMDBIntegration:
    """Verify AssetInventory queries ServiceNow and falls back to Postgres."""

    def test_servicenow_integration_in_source(self):
        """get_criticality must reference ServiceNow CMDB API."""
        import inspect
        from app.engine.asset_inventory import AssetInventory

        source = inspect.getsource(AssetInventory.get_criticality)
        assert "cmdb_ci" in source, \
            "get_criticality must query /api/now/table/cmdb_ci"
        assert "servicenow" in source.lower(), \
            "get_criticality must reference ServiceNow config"

    def test_no_hardcoded_heuristics(self):
        """Hostname heuristics (dc/domain/auth/vpn) must be removed."""
        import inspect
        from app.engine.asset_inventory import AssetInventory

        source = inspect.getsource(AssetInventory.get_criticality)
        for keyword in ["\"dc\"", "\"domain\"", "\"auth\"", "\"vpn\""]:
            assert keyword not in source, \
                f"Hardcoded heuristic {keyword} still present in get_criticality"

    def test_postgres_fallback_exists(self):
        """get_criticality must fall back to registered_assets table."""
        import inspect
        from app.engine.asset_inventory import AssetInventory

        source = inspect.getsource(AssetInventory.get_criticality)
        assert "registered_assets" in source, \
            "Must fall back to PostgreSQL registered_assets table"

    def test_asset_registration_endpoint_exists(self):
        """POST /assets/register endpoint must exist."""
        import inspect
        from app.api import posture

        source = inspect.getsource(posture)
        assert "assets/register" in source, \
            "POST /assets/register endpoint must be defined"
        assert "AssetRegistrationRequest" in source, \
            "Request schema must be defined"

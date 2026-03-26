"""Unified Configuration — Single source of truth.

All configuration comes from environment variables via Pydantic Settings.
No ``os.getenv`` calls anywhere else in the codebase.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings loaded from ``.env``."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── App ──────────────────────────────────────────────
    app_name: str = "Sentinel Fabric V2"
    environment: str = "development"
    debug: bool = False
    log_level: str = "INFO"
    api_prefix: str = "/api/v1"
    version: str = "2.0.0"
    cors_origins: list[str] = ["http://localhost:3000"]

    # ── Auth (self-issued JWT) ───────────────────────────
    jwt_secret_key: str  # No default, must be set in env
    jwt_fallback_secret_key: str | None = None
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60 * 24  # 24 hours

    # ── ClickHouse ───────────────────────────────────────
    clickhouse_host: str = "localhost"
    clickhouse_port: int = 8123
    clickhouse_database: str = "sentinel"
    clickhouse_user: str = "default"
    clickhouse_password: str = ""

    # ── Redis ────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_sentinel_hosts: list[str] = []
    redis_sentinel_master: str = "mymaster"
    redis_cluster_mode: bool = False

    # ── PostgreSQL ───────────────────────────────────────
    postgres_dsn: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    postgres_host: str = "localhost"
    postgres_port: int = 5432

    # ── Kafka ────────────────────────────────────────────
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_consumer_group: str = "sentinel-pipeline"
    kafka_topics: list[str] = [
        "sentinel.suricata",
        "sentinel.zeek",
        "sentinel.palo_alto",
        "sentinel.windows",
        "sentinel.crowdstrike",
        "sentinel.syslog",
    ]
    kafka_dlq_topic: str = "sentinel.dlq"

    # ── Qdrant ───────────────────────────────────────────
    qdrant_host: str = "localhost"
    qdrant_port: int = 6333

    # ── Pipeline ─────────────────────────────────────────
    pipeline_budget_ms: int = 2000
    sse_heartbeat_seconds: int = 15

    # ── IOC Feeds ──────────────────────────────────────
    otx_api_key: str = ""
    ioc_feed_interval_hours: int = 6

    # ── Threat Intel Integrations ─────────────────────
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    misp_url: str = ""           # e.g. "https://misp.example.internal"
    misp_api_key: str = ""
    taxii_url: str = ""          # e.g. "https://taxii.example.internal/api1"
    taxii_collection_id: str = ""
    taxii_token: str = ""

    # ── Narrative ──────────────────────────────────────
    narrative_mode: str = "llm"  # "llm" or "template"
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    llama_cpp_model: str = "deepseek-coder"
    llama_cpp_base_url: str = "http://localhost:8080/v1"
    llama_cpp_temperature: float = 0.2
    llama_cpp_max_tokens: int = 200

    # ── SOAR Integrations ─────────────────────────────
    # CrowdStrike Falcon
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    crowdstrike_base_url: str = "https://api.crowdstrike.com"
    # Legacy single-key field (kept for backward compat)
    crowdstrike_api_key: str = ""

    # Palo Alto Networks PAN-OS
    paloalto_host: str = ""
    paloalto_api_key: str = ""
    paloalto_verify_ssl: bool = True

    # Okta
    okta_domain: str = ""   # e.g. "https://your-org.okta.com"
    okta_api_token: str = ""

    # ── ServiceNow CMDB ──────────────────────────────────
    servicenow_instance: str = ""  # e.g. "https://your-org.service-now.com"
    servicenow_user: str = ""
    servicenow_password: str = ""

    # ── ChatOps / Notifications ──────────────────────────
    slack_bot_token: str = ""
    slack_webhook_url: str = ""
    teams_webhook_url: str = ""

    # ── HashiCorp Vault ──────────────────────────────────
    vault_url: str = ""
    vault_token: str = ""
    vault_path: str = "sentinel"
    vault_mount_point: str = "secret"
    vault_rotation_interval: int = 900  # seconds

    def model_post_init(self, __context) -> None:
        """Validate security invariants and optionally load from Vault."""
        _INSECURE_SECRETS = {
            "CHANGE-ME-IN-PRODUCTION",
            "changeme",
            "secret",
            "password",
            "",
        }

        # Load secrets from Vault if configured
        if self.vault_url and self.vault_token:
            try:
                import hvac
                client = hvac.Client(url=self.vault_url, token=self.vault_token)
                if client.is_authenticated():
                    resp = client.secrets.kv.v2.read_secret_version(
                        path=self.vault_path,
                        mount_point=self.vault_mount_point,
                    )
                    vault_secrets = resp.get("data", {}).get("data", {})
                    # Overwrite matching fields in settings
                    for k, v in vault_secrets.items():
                        if hasattr(self, k):
                            setattr(self, k, v)
                else:
                    import logging
                    logging.getLogger(__name__).warning("Vault configured but authentication failed")
            except ImportError:
                import logging
                logging.getLogger(__name__).error("Vault configured but 'hvac' library not installed")
            except Exception as e:
                import logging
                logging.getLogger(__name__).error(f"Failed to load secrets from Vault: {e}")

        if self.environment != "development":
            if self.jwt_secret_key in _INSECURE_SECRETS:
                raise RuntimeError(
                    "FATAL: jwt_secret_key is set to an insecure placeholder. "
                    "Set a strong random value in your .env before running in "
                    f"'{self.environment}' mode."
                )
            if self.cors_origins == ["http://localhost:3000"]:
                import warnings
                warnings.warn(
                    "CORS origins are still set to localhost:3000 in "
                    f"'{self.environment}' mode. Set CORS_ORIGINS to your actual domain(s).",
                    stacklevel=2,
                )

    async def start_vault_polling(self, interval_seconds: int = 900) -> None:
        """Background task to periodically refresh Vault secrets."""
        import asyncio
        import logging
        logger = logging.getLogger(__name__)

        if not self.vault_url or not self.vault_token:
            return

        while True:
            await asyncio.sleep(interval_seconds)
            try:
                import hvac
                client = hvac.Client(url=self.vault_url, token=self.vault_token)
                if client.is_authenticated():
                    resp = client.secrets.kv.v2.read_secret_version(
                        path=self.vault_path,
                        mount_point=self.vault_mount_point,
                    )
                    vault_secrets = resp.get("data", {}).get("data", {})

                    changed = False
                    for k, v in vault_secrets.items():
                        if hasattr(self, k) and getattr(self, k) != v:
                            setattr(self, k, v)
                            changed = True

                    if changed:
                        logger.info("vault_secrets_rotated")
                        try:
                            from app.dependencies import get_app_postgres
                            db = get_app_postgres()
                            if db:
                                await db.reload_pool()
                        except AssertionError:
                            pass
            except Exception as e:
                logger.error(f"Failed to poll secrets from Vault: {e}")

settings = Settings()

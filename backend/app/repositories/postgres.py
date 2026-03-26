"""PostgreSQL repository — transactional metadata.

Stores connector configs, tenant records, user accounts,
and analyst verdicts. ACID-guaranteed for data that updates
frequently and needs referential integrity.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Float, Boolean, DateTime, func, select, text, Index, Integer, JSON
from sqlalchemy.dialects.postgresql import TSVECTOR

from app.config import settings

import structlog

logger = structlog.get_logger(__name__)


# ── ORM Base ─────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


class ConnectorRecord(Base):
    __tablename__ = "connectors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    connection_pattern: Mapped[str] = mapped_column(String(16), nullable=False)
    config_json: Mapped[str] = mapped_column(String(4096), default="{}")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[Optional[str]] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[Optional[str]] = mapped_column(DateTime, onupdate=func.now())


class UserRecord(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="analyst")
    display_name: Mapped[Optional[str]] = mapped_column(String(128))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(32))
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)


class AnalystVerdict(Base):
    __tablename__ = "analyst_verdicts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    campaign_id: Mapped[Optional[str]] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)  # true_positive, false_positive
    analyst_id: Mapped[str] = mapped_column(String(36), nullable=False)
    notes: Mapped[Optional[str]] = mapped_column(String(2048))
    created_at: Mapped[Optional[str]] = mapped_column(DateTime, server_default=func.now())


class EntityEdge(Base):
    __tablename__ = "entity_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_entity: Mapped[str] = mapped_column(String(128), nullable=False)
    target_entity: Mapped[str] = mapped_column(String(128), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)  # lateral_movement, c2, exfil
    campaign_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float)
    first_seen: Mapped[Optional[str]] = mapped_column(DateTime, server_default=func.now())
    last_seen: Mapped[Optional[str]] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("idx_entity_edges_src", "tenant_id", "source_entity"),
    )


class PlaybookTemplate(Base):
    __tablename__ = "playbook_templates"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(32), default="Draft")
    nodes: Mapped[list[dict]] = mapped_column(JSON, default=list)
    created_at: Mapped[Optional[str]] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[Optional[str]] = mapped_column(DateTime, onupdate=func.now())


class PausedPlaybookState(Base):
    __tablename__ = "paused_playbook_states"

    approval_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    playbook_id: Mapped[str] = mapped_column(String(64), nullable=False)
    paused_node_index: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[Optional[str]] = mapped_column(DateTime, server_default=func.now())


class SoarAuditTrail(Base):
    __tablename__ = "soar_audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    playbook_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[Optional[str]] = mapped_column(DateTime, server_default=func.now())


class IncidentAnnotation(Base):
    __tablename__ = "incident_annotations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    content: Mapped[str] = mapped_column(String(4096), nullable=False)
    annotation_type: Mapped[str] = mapped_column(String(32), default="note")
    created_at: Mapped[Optional[str]] = mapped_column(DateTime, server_default=func.now())


class ReportMetadata(Base):
    __tablename__ = "report_metadata"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    report_name: Mapped[str] = mapped_column(String(256), nullable=False)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_by: Mapped[str] = mapped_column(String(36), nullable=False)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer)
    created_at: Mapped[Optional[str]] = mapped_column(DateTime, server_default=func.now())


class MetaLearnerWeights(Base):
    """Persisted meta-learner fusion weights.

    Single-row table keyed by tenant_id. Updated on every analyst
    verdict to ensure weights survive service restarts.
    """
    __tablename__ = "meta_learner_weights"

    tenant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    weight_ensemble: Mapped[float] = mapped_column(Float, default=0.25)
    weight_vae: Mapped[float] = mapped_column(Float, default=0.20)
    weight_hst: Mapped[float] = mapped_column(Float, default=0.15)
    weight_temporal: Mapped[float] = mapped_column(Float, default=0.20)
    weight_adversarial: Mapped[float] = mapped_column(Float, default=0.20)
    verdicts_processed: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[Optional[str]] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())


# ── Repository ───────────────────────────────────────────

class PostgresRepository:
    """Async PostgreSQL repository for transactional metadata."""

    def __init__(self) -> None:
        self._engine = None
        self._session_factory = None

    async def connect(self) -> None:
        self._engine = create_async_engine(
            settings.postgres_dsn,
            echo=settings.debug,
            pool_size=10,
            max_overflow=20,
        )
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            try:
                # Safely add TSVECTOR column and index for existing databases
                await conn.execute(text("ALTER TABLE analyst_verdicts ADD COLUMN IF NOT EXISTS notes_tsv tsvector GENERATED ALWAYS AS (to_tsvector('english', coalesce(notes, ''))) STORED;"))
                await conn.execute(text("CREATE INDEX IF NOT EXISTS analyst_verdicts_notes_tsv_idx ON analyst_verdicts USING GIN (notes_tsv);"))
            except Exception as e:
                logger.warning("Failed to alter table analyst_verdicts (expected if SQLite test DB)", error=str(e))
        logger.info("postgres_connected")

    async def close(self) -> None:
        if self._engine:
            await self._engine.dispose()

    def _session(self) -> AsyncSession:
        assert self._session_factory, "PostgreSQL not initialized"
        return self._session_factory()

    # ── Connectors ───────────────────────────────────────

    async def list_connectors(self, tenant_id: str) -> list[ConnectorRecord]:
        async with self._session() as session:
            result = await session.execute(
                select(ConnectorRecord).where(ConnectorRecord.tenant_id == tenant_id)
            )
            return list(result.scalars().all())

    async def save_connector(self, connector: ConnectorRecord) -> None:
        async with self._session() as session:
            session.add(connector)
            await session.commit()

    # ── Users ────────────────────────────────────────────

    async def get_user_by_email(self, email: str) -> Optional[UserRecord]:
        async with self._session() as session:
            result = await session.execute(
                select(UserRecord).where(UserRecord.email == email)
            )
            return result.scalar_one_or_none()

    async def create_user(self, user: UserRecord) -> None:
        async with self._session() as session:
            session.add(user)
            await session.commit()

    async def update_user_mfa(self, email: str, secret: Optional[str], enabled: bool) -> None:
        async with self._session() as session:
            result = await session.execute(select(UserRecord).where(UserRecord.email == email))
            user = result.scalar_one_or_none()
            if user:
                user.mfa_secret = secret
                user.mfa_enabled = enabled
                await session.commit()

    # ── Verdicts ─────────────────────────────────────────

    async def save_verdict(self, verdict: AnalystVerdict) -> None:
        async with self._session() as session:
            session.add(verdict)
            await session.commit()

    async def get_verdicts(
        self, tenant_id: str, limit: int = 100
    ) -> list[AnalystVerdict]:
        async with self._session() as session:
            result = await session.execute(
                select(AnalystVerdict)
                .where(AnalystVerdict.tenant_id == tenant_id)
                .order_by(AnalystVerdict.created_at.desc())
                .limit(limit)
            )
            return list(result.scalars().all())

    async def search_verdicts_by_note(self, tenant_id: str, query: str, limit: int = 10) -> list[dict]:
        """Search analyst notes using PostgreSQL full-text search (tsvector)."""
        sql = text("""
            SELECT id, event_id, campaign_id, verdict, analyst_id, notes, created_at
            FROM analyst_verdicts
            WHERE tenant_id = :tenant_id
              AND notes_tsv @@ plainto_tsquery('english', :query)
            ORDER BY ts_rank(notes_tsv, plainto_tsquery('english', :query)) DESC
            LIMIT :limit
        """)
        async with self._session() as session:
            result = await session.execute(sql, {"tenant_id": tenant_id, "query": query, "limit": limit})
            return [dict(row) for row in result.mappings().all()]

    # ── Graph Database (Entity Edges) ────────────────────

    async def save_entity_edge(self, edge: EntityEdge) -> None:
        async with self._session() as session:
            session.add(edge)
            await session.commit()

    async def get_entity_paths(self, tenant_id: str, start_entity: str, max_depth: int = 3) -> list[dict]:
        """Recursive CTE for resolving lateral movement and activity paths."""
        query = text(f"""
        WITH RECURSIVE path_search AS (
            -- Base case
            SELECT id, source_entity, target_entity, relationship_type, campaign_id, 1 as depth, ARRAY[source_entity, target_entity] as path
            FROM entity_edges
            WHERE tenant_id = :tenant_id AND source_entity = :start_entity

            UNION ALL

            -- Recursive step
            SELECT e.id, e.source_entity, e.target_entity, e.relationship_type, e.campaign_id, p.depth + 1, p.path || e.target_entity
            FROM entity_edges e
            JOIN path_search p ON e.source_entity = p.target_entity
            WHERE e.tenant_id = :tenant_id AND p.depth < :max_depth
              AND NOT (e.target_entity = ANY(p.path)) -- Prevent cycles
        )
        SELECT * FROM path_search
        ORDER BY depth ASC
        """)
        async with self._session() as session:
            result = await session.execute(query, {"tenant_id": tenant_id, "start_entity": start_entity, "max_depth": max_depth})
            return [dict(row) for row in result.mappings().all()]

    # ── SOAR Playbooks ───────────────────────────────────

    async def get_playbook(self, playbook_id: str) -> Optional[PlaybookTemplate]:
        async with self._session() as session:
            result = await session.execute(
                select(PlaybookTemplate).where(PlaybookTemplate.id == playbook_id)
            )
            return result.scalar_one_or_none()

    async def list_playbooks(self) -> list[PlaybookTemplate]:
        async with self._session() as session:
            result = await session.execute(
                select(PlaybookTemplate).order_by(PlaybookTemplate.created_at.desc())
            )
            return list(result.scalars().all())

    async def seed_playbooks_if_empty(self) -> None:
        """Seeds the database with default playbooks if none exist."""
        async with self._session() as session:
            result = await session.execute(select(func.count(PlaybookTemplate.id)))
            if result.scalar() == 0:
                templates = [
                    PlaybookTemplate(
                        id="isolate-endpoint",
                        name="Isolate Endpoint",
                        description="Blocks all network traffic except management interfaces.",
                        status="Active",
                        nodes=[{"id": "node_1", "action_type": "isolate_host", "provider": "crowdstrike", "params": {}}]
                    ),
                    PlaybookTemplate(
                        id="block-ip",
                        name="Block IP on Firewall",
                        description="Adds malicious IP to the global drop list.",
                        status="Active",
                        nodes=[{"id": "node_1", "action_type": "block_ip", "provider": "paloalto", "params": {}}]
                    ),
                    PlaybookTemplate(
                        id="quarantine-user",
                        name="Reset User Credentials",
                        description="Forces immediate password reset and revokes sessions.",
                        status="Active",
                        nodes=[{"id": "node_1", "action_type": "quarantine_user", "provider": "okta", "params": {}}]
                    )
                ]
                session.add_all(templates)
                await session.commit()
                logger.info("seeded_playbook_templates")

    async def create_playbook(self, name: str, description: str, nodes: list) -> PlaybookTemplate:
        import uuid
        playbook = PlaybookTemplate(
            id=str(uuid.uuid4())[:8],
            name=name,
            description=description,
            status="Draft",
            nodes=nodes,
        )
        async with self._session() as session:
            session.add(playbook)
            await session.commit()
        return playbook

    # ── Paused Playbook State ───────────────────────────

    async def save_paused_state(self, playbook_id: str, node_index: int, approval_id: str) -> None:
        state = PausedPlaybookState(
            approval_id=approval_id,
            playbook_id=playbook_id,
            paused_node_index=node_index,
        )
        async with self._session() as session:
            session.add(state)
            await session.commit()

    async def get_paused_state(self, approval_id: str) -> Optional[PausedPlaybookState]:
        async with self._session() as session:
            result = await session.execute(
                select(PausedPlaybookState).where(PausedPlaybookState.approval_id == approval_id)
            )
            return result.scalar_one_or_none()

    async def clear_paused_state(self, approval_id: str) -> None:
        async with self._session() as session:
            state = await session.get(PausedPlaybookState, approval_id)
            if state:
                await session.delete(state)
                await session.commit()

    # ── SOAR Audit Trail ─────────────────────────────────

    async def save_soar_audit_log(self, playbook_id: str, node_id: str, action_type: str, provider: str, status: str, params: dict) -> None:
        log_entry = SoarAuditTrail(
            playbook_id=playbook_id,
            node_id=node_id,
            action_type=action_type,
            provider=provider,
            status=status,
            params=params,
        )
        async with self._session() as session:
            session.add(log_entry)
            await session.commit()

    # ── Collaboration Persistence ───────────────────────

    async def save_incident_annotation(self, incident_id: str, user_id: str, content: str) -> None:
        annotation = IncidentAnnotation(
            incident_id=incident_id,
            user_id=user_id,
            content=content,
            annotation_type="note",
        )
        async with self._session() as session:
            session.add(annotation)
            await session.commit()

    async def save_incident_tag(self, incident_id: str, user_id: str, tag: str) -> None:
        annotation = IncidentAnnotation(
            incident_id=incident_id,
            user_id=user_id,
            content=tag,
            annotation_type="tag",
        )
        async with self._session() as session:
            session.add(annotation)
            await session.commit()

    # ── Reporting ────────────────────────────────────────

    async def save_report_metadata(self, report: ReportMetadata) -> None:
        async with self._session() as session:
            session.add(report)
            await session.commit()

    async def list_reports(self, tenant_id: str, limit: int = 50) -> list[ReportMetadata]:
        async with self._session() as session:
            result = await session.execute(
                select(ReportMetadata)
                .where(ReportMetadata.tenant_id == tenant_id)
                .order_by(ReportMetadata.created_at.desc())
                .limit(limit)
            )
            return list(result.scalars().all())

    # -- Meta-Learner Weights ────────────────────────────

    async def load_meta_learner_weights(self, tenant_id: str = "default") -> Optional[list[float]]:
        """Load persisted meta-learner weights for a tenant."""
        async with self._session() as session:
            result = await session.execute(
                select(MetaLearnerWeights).where(MetaLearnerWeights.tenant_id == tenant_id)
            )
            row = result.scalar_one_or_none()
            if row:
                return [
                    row.weight_ensemble,
                    row.weight_vae,
                    row.weight_hst,
                    row.weight_temporal,
                    row.weight_adversarial,
                ]
        return None

    async def save_meta_learner_weights(
        self, weights: list[float], verdicts_processed: int, tenant_id: str = "default"
    ) -> None:
        """Upsert meta-learner weights for a tenant."""
        assert len(weights) == 5, f"Expected 5 weights, got {len(weights)}"
        async with self._session() as session:
            result = await session.execute(
                select(MetaLearnerWeights).where(MetaLearnerWeights.tenant_id == tenant_id)
            )
            row = result.scalar_one_or_none()
            if row:
                row.weight_ensemble = weights[0]
                row.weight_vae = weights[1]
                row.weight_hst = weights[2]
                row.weight_temporal = weights[3]
                row.weight_adversarial = weights[4]
                row.verdicts_processed = verdicts_processed
            else:
                session.add(MetaLearnerWeights(
                    tenant_id=tenant_id,
                    weight_ensemble=weights[0],
                    weight_vae=weights[1],
                    weight_hst=weights[2],
                    weight_temporal=weights[3],
                    weight_adversarial=weights[4],
                    verdicts_processed=verdicts_processed,
                ))
            await session.commit()
        logger.info("meta_learner_weights_persisted", tenant_id=tenant_id, weights=weights)

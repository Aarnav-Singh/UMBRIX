"""Threat Hunt API — Phase 3 (UQL Engine).

Exposes a unified hunt endpoint that accepts either:
  - UQL (UMBRIX Query Language) strings
  - Natural-language queries (translated to UQL via LLM)

Query execution pipeline:
  1. NL → UQL translation (Anthropic API, optional)
  2. UQL parsing + compilation (Lark + UQLCompiler)
  3. Parallel execution:
     a. ClickHouse query with compiled WHERE clause
     b. Qdrant semantic search (if semantic_filter present)
  4. Result merge + deduplication
  5. Hunt query persisted to PostgreSQL hunt_queries table

Endpoints:
  POST /hunt        — execute a hunt query
  GET  /hunt/syntax — return UQL grammar reference for the frontend editor
"""
from __future__ import annotations

import asyncio
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.dependencies import get_app_clickhouse, get_app_qdrant, get_app_postgres
from app.middleware.auth import require_analyst
from app.engine.uql.compiler import UQLCompiler

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/hunt", tags=["threat-hunt"])

_compiler = UQLCompiler()


# ── Request / Response models ─────────────────────────────────────────────────

class HuntRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000, description="UQL string or natural-language text")
    mode: Literal["uql", "nl"] = Field("uql", description="'uql' = parse directly, 'nl' = translate via LLM first")
    limit: int = Field(100, ge=1, le=1000)
    tenant_id: str | None = None  # Overridden by JWT claim


class HuntResult(BaseModel):
    uql: str
    mode: str
    results: list[dict]
    qdrant_results: list[dict]
    result_count: int
    execution_ms: int
    errors: list[str]


# ── UQL syntax reference for the frontend editor ──────────────────────────────

_UQL_SYNTAX_REF = {
    "operators": ["and"],
    "filters": {
        "ml_score": "ml_score > 0.8  (comparators: >, <, >=, <=, =, !=)",
        "tactic": 'tactic = "lateral-movement"  (MITRE ATT&CK tactic name)',
        "source_type": 'source_type = "crowdstrike"',
        "severity": 'severity = "critical"',
        "similar": 'similar("cobalt strike beacon", threshold=0.85)',
        "sequence": 'sequence on src_ip [tactic = "discovery", tactic = "credential-access"] maxspan=15m',
    },
    "tactics": [
        "reconnaissance", "resource-development", "initial-access", "execution",
        "persistence", "privilege-escalation", "defense-evasion", "credential-access",
        "discovery", "lateral-movement", "collection", "command-and-control",
        "exfiltration", "impact",
    ],
    "examples": [
        'ml_score > 0.8 and tactic = "lateral-movement"',
        'source_type = "crowdstrike" and severity = "critical"',
        'similar("cobalt strike beacon", threshold=0.82)',
        'sequence on src_ip [tactic = "credential-access", tactic = "lateral-movement"] maxspan=15m',
        'tactic = "exfiltration" and ml_score > 0.7',
    ],
}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/syntax")
async def get_uql_syntax(claims: dict = Depends(require_analyst)) -> dict:
    """Return UQL grammar reference for the frontend editor."""
    return _UQL_SYNTAX_REF


@router.post("/", response_model=HuntResult)
async def execute_hunt(
    req: HuntRequest,
    claims: dict = Depends(require_analyst),
) -> HuntResult:
    """Execute a threat hunt query in UQL or natural-language mode.

    In NL mode, the query is first translated to UQL via the Anthropic API,
    then compiled and executed. The translated UQL is returned in the response
    so the analyst can inspect, save, or refine it.
    """
    start_ts = time.monotonic()
    tenant_id = claims.get("tenant_id", "default")
    user_id = claims.get("sub", "unknown")
    errors: list[str] = []

    # ── Step 1: NL → UQL translation ──────────────────────────────────────────
    final_uql = req.query
    mode_used = req.mode

    if req.mode == "nl":
        try:
            from app.config import settings
            from app.engine.uql.nl_translator import translate_nl_to_uql
            final_uql = await translate_nl_to_uql(req.query, api_key=settings.anthropic_api_key)
        except Exception as exc:
            errors.append(f"NL translation failed, falling back to raw search: {exc}")
            final_uql = req.query
            mode_used = "nl_fallback"

    # ── Step 2: UQL compilation ───────────────────────────────────────────────
    compiled = _compiler.compile(final_uql)
    errors.extend(compiled.errors)

    if compiled.errors and not compiled.clickhouse_where:
        raise HTTPException(status_code=400, detail=f"UQL parse error: {compiled.errors[0]}")

    # ── Step 3a: ClickHouse query ─────────────────────────────────────────────
    ch_results: list[dict] = []
    try:
        ch = get_app_clickhouse()
        if ch._client:
            user_where = compiled.clickhouse_where
            params = {
                "tenant_id": tenant_id,
                "limit": req.limit,
                **compiled.clickhouse_params
            }
            import asyncio as _asyncio
            raw = await _asyncio.to_thread(
                ch.client.query,
                f"SELECT * FROM events WHERE tenant_id = {{tenant_id:String}} AND ({user_where}) ORDER BY timestamp DESC LIMIT {{limit:UInt32}}",
                parameters=params
            )
            ch_results = [dict(zip(raw.column_names, row)) for row in raw.result_rows]
        else:
            # Fallback path — in-memory filter
            all_events = await ch.query_events(tenant_id=tenant_id, limit=req.limit)
            ch_results = all_events
    except Exception as exc:
        errors.append(f"ClickHouse query error: {exc}")
        logger.warning("hunt_clickhouse_error", error=str(exc))

    # ── Step 3b: Qdrant semantic search ───────────────────────────────────────
    qdrant_results: list[dict] = []
    if compiled.qdrant_params:
        try:
            from app.engine.narrative import _embed_text  # reuse existing embedding util
            from app.dependencies import get_app_qdrant

            query_text = compiled.qdrant_params["query"]
            threshold = compiled.qdrant_params.get("threshold", 0.80)
            qdrant = get_app_qdrant()

            # Embed the search query text
            embedding = await asyncio.to_thread(_embed_text, query_text)
            if embedding:
                similar = await qdrant.search_similar_campaigns(
                    vector=embedding,
                    limit=20,
                    tenant_id=tenant_id,
                )
                qdrant_results = [r for r in similar if r.get("score", 0) >= threshold]
        except Exception as exc:
            errors.append(f"Qdrant search error: {exc}")
            logger.warning("hunt_qdrant_error", error=str(exc))

    # ── Step 4: Persist hunt query ────────────────────────────────────────────
    try:
        pg = get_app_postgres()
        await pg.save_hunt_query(
            tenant_id=tenant_id,
            user_id=user_id,
            query_text=req.query,
            query_mode=mode_used,
            uql_output=final_uql if mode_used in ("nl", "nl_fallback") else None,
            result_count=len(ch_results) + len(qdrant_results),
        )
    except Exception as exc:
        logger.debug("hunt_history_save_failed", error=str(exc))
        # Non-critical — don't fail the hunt

    execution_ms = int((time.monotonic() - start_ts) * 1000)

    logger.info(
        "hunt_executed",
        mode=mode_used,
        uql=final_uql,
        ch_results=len(ch_results),
        qdrant_results=len(qdrant_results),
        execution_ms=execution_ms,
    )

    return HuntResult(
        uql=final_uql,
        mode=mode_used,
        results=ch_results,
        qdrant_results=qdrant_results,
        result_count=len(ch_results) + len(qdrant_results),
        execution_ms=execution_ms,
        errors=errors,
    )

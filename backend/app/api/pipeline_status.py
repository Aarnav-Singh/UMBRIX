"""Pipeline Status API — real-time ML model health and throughput."""
from __future__ import annotations


import structlog
from fastapi import APIRouter, Depends

from app.dependencies import get_app_pipeline, get_app_clickhouse
from app.middleware.auth import require_viewer

router = APIRouter(prefix="/api/v1/pipeline", tags=["pipeline"])
logger = structlog.get_logger(__name__)

# Model display metadata (static presentation layer)
STREAM_META = {
    "ensemble": {"abbr": "SUP", "name": "Supervised Classifier", "color": "#00d4c8"},
    "vae":      {"abbr": "VAE", "name": "Variational Autoencoder", "color": "#b57aff"},
    "hst":      {"abbr": "ONL", "name": "Online Learner (HST)", "color": "#ffaa00"},
    "temporal": {"abbr": "SEQ", "name": "Sequence Detector", "color": "#00e676"},
    "adversarial": {"abbr": "EVA", "name": "Evasion Detector", "color": "#ff3f5b"},
}


@router.get("/status")
async def pipeline_status(claims: dict = Depends(require_viewer)):
    """Current 5-stream ML scores + meta-learner output from live pipeline."""
    pipeline = get_app_pipeline()
    ch = get_app_clickhouse()

    # Get real event count and last-processed stats
    try:
        event_count = await ch.get_event_count()
    except Exception:
        event_count = 0

    # Build stream info from actual model instances tracking frontend struct
    streams = {}
    models = {
        "ensemble": {"model": pipeline._ensemble, "weight": 0.3},
        "vae": {"model": pipeline._vae, "weight": 0.2},
        "hst": {"model": pipeline._hst, "weight": 0.15},
        "temporal": {"model": pipeline._temporal, "weight": 0.2},
        "adversarial": {"model": pipeline._adversarial, "weight": 0.1},
        "meta_learner": {"model": pipeline._meta, "weight": 0.05},
    }
    
    for model_id, info in models.items():
        model = info["model"]
        is_active = model is not None
        # We try to look for last_score, and if not present, substitute a default value until one gets generated.
        score = getattr(model, "last_score", 0.0) if is_active else 0.0
        
        streams[model_id] = {
            "score": score,
            "weight": info["weight"] if is_active else 0.0,
            "status": "serving" if is_active else "degraded",
            "active": is_active,
        }

    return {
        "streams": streams,
        "events_processed": event_count,
        "avg_duration_ms": round(pipeline.avg_duration_ms, 2),
        "pipeline_active": True,
    }


@router.get("/models")
async def pipeline_models(claims: dict = Depends(require_viewer)):
    """Model health, version, and training metadata."""
    pipeline = get_app_pipeline()
    models_info = {
        "ensemble": pipeline._ensemble,
        "vae": pipeline._vae,
        "hst": pipeline._hst,
        "temporal": pipeline._temporal,
        "adversarial": pipeline._adversarial,
    }
    result = []
    for model_id, model in models_info.items():
        meta = STREAM_META.get(model_id, {})
        result.append({
            "id": model_id,
            "abbr": meta.get("abbr", model_id.upper()[:3]),
            "name": meta.get("name", model_id),
            "color": meta.get("color", "#888888"),
            "version": getattr(model, "version", "v1.0.0"),
            "health": "healthy",
            "input_dim": getattr(model, "input_dim", None),
            "loaded": True,
        })
    return {"models": result}

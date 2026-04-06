"""Prometheus metrics exporter for the backend."""
from __future__ import annotations

from fastapi import FastAPI
from prometheus_client import CONTENT_TYPE_LATEST
from prometheus_client import Counter
from prometheus_client import Gauge
from prometheus_client import Histogram
from prometheus_client import generate_latest
from fastapi.responses import Response
import time

# Metrics definitions
REQUEST_COUNT = Counter(
    "http_request_total", 
    "Total HTTP Requests", 
    ["method", "endpoint", "http_status"]
)

REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds", 
    "HTTP Request Latency", 
    ["method", "endpoint"]
)

PIPELINE_EVENT_TOTAL = Counter(
    "pipeline_events_total", 
    "Total events processed by the 15-step pipeline", 
    ["source", "severity", "status"]
)

PIPELINE_STEP_LATENCY = Histogram(
    "pipeline_step_duration_seconds", 
    "Latency per pipeline step", 
    ["step_name"]
)

from prometheus_client import Gauge

ENSEMBLE_SCORE = Gauge(
    "ensemble_score_current",
    "Latest Ensemble score seen by the pipeline"
)

VAE_ANOMALY_SCORE = Gauge(
    "vae_anomaly_score_current",
    "Latest VAE anomaly score seen by the pipeline"
)

TEMPORAL_ANOMALY_SCORE = Gauge(
    "temporal_anomaly_score_current",
    "Latest Temporal anomaly score seen by the pipeline"
)

ADVERSARIAL_SCORE = Gauge(
    "adversarial_score_current",
    "Latest Adversarial score seen by the pipeline"
)

META_SCORE = Gauge(
    "meta_score_current",
    "Latest Meta score calculated by the pipeline"
)


def setup_metrics(app: FastAPI):
    """Register the /metrics endpoint and middleware."""
    
    @app.middleware("http")
    async def prometheus_middleware(request, call_next):
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        
        # Increment request counter
        REQUEST_COUNT.labels(
            method=request.method,
            endpoint=request.url.path,
            http_status=response.status_code
        ).inc()
        
        # Observe request latency
        REQUEST_LATENCY.labels(
            method=request.method,
            endpoint=request.url.path
        ).observe(duration)
        
        return response

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

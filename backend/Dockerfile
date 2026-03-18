FROM python:3.11-slim as base

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Add healthcheck curl
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY . .

# ── API Stage ─────────────────────────────────────
FROM base as api
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ── Worker Stage ──────────────────────────────────
FROM base as worker
# The worker doesn't serve HTTP natively (though it could for metrics), but it listens to Kafka
CMD ["python", "worker.py"]

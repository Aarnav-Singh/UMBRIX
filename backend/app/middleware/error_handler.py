"""Centralized error handling middleware.

Maps domain exceptions to HTTP status codes.
All unexpected errors are logged via structlog.
"""
from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse

import structlog

from app.middleware.request_id import request_id_ctx_var

logger = structlog.get_logger(__name__)


class DomainError(Exception):
    """Base class for all domain-level errors."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class NotFoundError(DomainError):
    def __init__(self, resource: str, identifier: str) -> None:
        super().__init__(f"{resource} '{identifier}' not found", status_code=404)


class AuthenticationError(DomainError):
    def __init__(self, detail: str = "Invalid credentials") -> None:
        super().__init__(detail, status_code=401)


class AuthorizationError(DomainError):
    def __init__(self, detail: str = "Insufficient permissions") -> None:
        super().__init__(detail, status_code=403)


class ValidationError(DomainError):
    def __init__(self, detail: str) -> None:
        super().__init__(detail, status_code=422)


async def domain_error_handler(request: Request, exc: DomainError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.message,
            "request_id": request_id_ctx_var.get() or None,
        },
    )


async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    rid = request_id_ctx_var.get() or None
    logger.exception("unhandled_error", error=str(exc), request_id=rid)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "request_id": rid,
        },
    )

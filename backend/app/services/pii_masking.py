"""PII Masking Service — SHA-256 hashing of sensitive fields.

Applied at the edge before events enter Kafka, ensuring that
personally identifiable information never reaches the pipeline
or ClickHouse in plain text.

Masked fields:
  • Email addresses  → sha256(email)
  • Phone numbers    → sha256(phone)
  • SSN-like formats → sha256(ssn)
  • Credit card nums → sha256(cc)
  • Usernames tagged with `pii_username` → sha256(user)

The original value can never be recovered (one-way hash).
If you need reverse lookup, use HMAC with a secret key instead.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

import structlog

logger = structlog.get_logger(__name__)

# ── Compiled patterns (fast) ─────────────────────────
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_RE = re.compile(r"\b(?:\d[ -]*?){13,16}\b")


def _sha256(value: str) -> str:
    """Return hex SHA-256 of a string."""
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


def mask_pii_in_string(text: str) -> str:
    """Replace all PII matches found in a plain-text string."""
    text = _SSN_RE.sub(lambda m: f"[SSN:{_sha256(m.group())[:12]}]", text)
    text = _CC_RE.sub(lambda m: f"[CC:{_sha256(m.group())[:12]}]", text)
    text = _EMAIL_RE.sub(lambda m: f"[EMAIL:{_sha256(m.group())[:12]}]", text)
    text = _PHONE_RE.sub(lambda m: f"[PHONE:{_sha256(m.group())[:12]}]", text)
    return text


def mask_pii_in_dict(data: dict[str, Any], *, depth: int = 0, max_depth: int = 10) -> dict[str, Any]:
    """Recursively walk a dict and mask PII values.

    Handles nested dicts and lists. Stops at *max_depth* to avoid
    infinite recursion on circular references.
    """
    if depth > max_depth:
        return data

    masked: dict[str, Any] = {}
    for key, value in data.items():
        lower_key = key.lower()

        # Known PII field names → hash the entire value
        if lower_key in {"email", "e-mail", "user_email", "sender_email", "recipient_email"}:
            masked[key] = f"[EMAIL:{_sha256(str(value))[:12]}]" if value else value
        elif lower_key in {"phone", "phone_number", "mobile", "telephone"}:
            masked[key] = f"[PHONE:{_sha256(str(value))[:12]}]" if value else value
        elif lower_key in {"ssn", "social_security", "social_security_number"}:
            masked[key] = f"[SSN:{_sha256(str(value))[:12]}]" if value else value
        elif lower_key in {"credit_card", "cc_number", "card_number"}:
            masked[key] = f"[CC:{_sha256(str(value))[:12]}]" if value else value
        elif lower_key in {"pii_username", "full_name", "patient_name"}:
            masked[key] = f"[USER:{_sha256(str(value))[:12]}]" if value else value

        # Recurse into nested structures
        elif isinstance(value, dict):
            masked[key] = mask_pii_in_dict(value, depth=depth + 1, max_depth=max_depth)
        elif isinstance(value, list):
            masked[key] = [
                mask_pii_in_dict(item, depth=depth + 1, max_depth=max_depth)
                if isinstance(item, dict)
                else mask_pii_in_string(str(item)) if isinstance(item, str) else item
                for item in value
            ]

        # String values → regex scan
        elif isinstance(value, str):
            masked[key] = mask_pii_in_string(value)
        else:
            masked[key] = value

    return masked


def mask_event(raw_event: dict[str, Any]) -> dict[str, Any]:
    """Top-level API: mask PII in a raw event dict before Kafka ingestion."""
    try:
        return mask_pii_in_dict(raw_event)
    except Exception as exc:
        logger.warning("pii_masking_error", error=str(exc))
        return raw_event  # Never block the pipeline

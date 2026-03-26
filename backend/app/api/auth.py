"""Authentication API — login endpoint and auth re-exports.

Per @cc-skill-security-review: authorization checks before sensitive ops.
Per @auth-implementation-patterns: centralized auth module for re-export.
"""
from __future__ import annotations
import bcrypt
from fastapi import APIRouter, HTTPException, Request, Depends
from pydantic import BaseModel
from app.middleware.auth import (
    create_access_token,
    require_auth,
    require_role,
    require_admin,
    require_analyst,
    require_viewer,
    Role,
    AuditLogger,
)
from app.dependencies import get_app_postgres, get_app_ratelimiter
import structlog

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


# ── Bridge dependency for existing route imports ──────────
# settings.py, sigma_rules.py, soar.py import `get_current_user`
# from this module. This bridges to the middleware's `require_auth`.

async def get_current_user(claims: dict = Depends(require_auth)) -> dict:
    """FastAPI dependency — validates JWT and returns claims dict.

    Acts as the public interface that API routes import.
    Returns the decoded JWT claims (sub, tenant_id, role, etc.).
    """
    return claims


class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: str | None = None

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: str

@router.post("/login", response_model=LoginResponse)
async def login(
    req: LoginRequest,
    request: Request,
    limiter = Depends(get_app_ratelimiter)
):
    await limiter.check_rate_limit(request, limit=5, window_seconds=60)
    postgres = get_app_postgres()
    user = await postgres.get_user_by_email(req.username)

    if not user or not bcrypt.checkpw(req.password.encode('utf-8'), user.password_hash.encode('utf-8')):
        AuditLogger.log("login_failed", request=request, detail=f"user={req.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        AuditLogger.log("login_disabled", request=request, detail=f"user={req.username}")
        raise HTTPException(status_code=401, detail="User account is disabled")

    # MFA Validation
    if user.mfa_enabled:
        if not req.mfa_code:
            raise HTTPException(status_code=401, detail="mfa_required")
        import pyotp
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(req.mfa_code):
            AuditLogger.log("login_mfa_failed", request=request, detail=f"user={req.username}")
            raise HTTPException(status_code=401, detail="Invalid MFA code")

    token = create_access_token(
        subject=user.email,
        tenant_id=user.tenant_id,
        role=user.role,
    )
    AuditLogger.log(
        "login_success",
        request=request,
        claims={"sub": user.email, "tenant_id": user.tenant_id, "role": user.role},
    )
    return LoginResponse(access_token=token, tenant_id=user.tenant_id)


class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str

@router.post("/enable-mfa", response_model=MFASetupResponse)
async def enable_mfa(
    request: Request,
    claims: dict = Depends(require_auth),
    postgres = Depends(get_app_postgres)
):
    """Generate a new TOTP secret for the user."""
    import pyotp
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=claims["sub"], issuer_name="Sentinel Fabric V2")
    
    await postgres.update_user_mfa(email=claims["sub"], secret=secret, enabled=False)
    AuditLogger.log("mfa_setup_initiated", request=request, claims=claims)
    
    return MFASetupResponse(secret=secret, provisioning_uri=uri)

class MFAVerifyRequest(BaseModel):
    mfa_code: str

@router.post("/verify-mfa-setup")
async def verify_mfa_setup(
    req: MFAVerifyRequest,
    request: Request,
    claims: dict = Depends(require_auth),
    postgres = Depends(get_app_postgres)
):
    """Verify the generated TOTP secret and enable MFA permanently."""
    user = await postgres.get_user_by_email(claims["sub"])
    if not user or not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA setup not initiated.")
        
    import pyotp
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(req.mfa_code):
        AuditLogger.log("mfa_setup_failed", request=request, claims=claims)
        raise HTTPException(status_code=400, detail="Invalid code.")
        
    await postgres.update_user_mfa(email=claims["sub"], secret=user.mfa_secret, enabled=True)
    AuditLogger.log("mfa_enabled_successfully", request=request, claims=claims)
    return {"status": "success", "message": "MFA enabled"}


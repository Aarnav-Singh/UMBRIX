"""Sigma Rule Management APIs — Addendum A1.

Provides:
  GET  /sigma-rules/          — list all rules
  GET  /sigma-rules/{id}      — get single rule
  POST /sigma-rules/          — create rule (admin)
  PUT  /sigma-rules/{id}      — update rule (admin)
  DELETE /sigma-rules/{id}    — delete rule (admin)
  GET  /sigma-rules/export    — export all rules as ZIP [NEW]
  POST /sigma-rules/import    — import ZIP or YAML bundle [NEW]
  GET  /sigma-rules/coverage  — ATT&CK coverage summary [NEW]
"""

import io
import os
import zipfile
from pathlib import Path
from typing import Dict, Any, Optional
import yaml
from app.api.auth import require_admin, require_analyst, AuditLogger
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/sigma-rules", tags=["Sigma Rules"])

# Define the rules directory
RULES_DIR = Path(__file__).parent.parent / "engine" / "sigma_rules"

class MitreConfig(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str

class SigmaRuleRequest(BaseModel):
    id: str
    name: str
    mitre: MitreConfig
    conditions: Dict[str, Any]
    confidence: float

def ensure_rules_dir():
    if not RULES_DIR.exists():
        RULES_DIR.mkdir(parents=True, exist_ok=True)

def find_rule_file(rule_id: str) -> Optional[Path]:
    """Helper to find a rule file by checking its contents or filename."""
    ensure_rules_dir()
    
    # Fast path: check if file named rule_id.yml exists
    fast_path = RULES_DIR / f"{rule_id}.yml"
    if fast_path.is_file():
        try:
            with open(fast_path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
            if content and content.get("id") == rule_id:
                return fast_path
        except Exception:
            pass

    # Slow path: iterate over all files
    for yml_file in RULES_DIR.glob("*.yml"):
        try:
            with open(yml_file, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
            if content and content.get("id") == rule_id:
                return yml_file
        except Exception:
            continue
            
    return None

@router.get("/")
async def list_sigma_rules(claims: dict = Depends(require_analyst)):
    """List all custom Sigma rules. Requires analyst role."""
    ensure_rules_dir()
    rules = []
    for yml_file in RULES_DIR.glob("*.yml"):
        try:
            with open(yml_file, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
            if content:
                rules.append(content)
        except Exception as e:
            logger.warning("failed_to_read_rule_file", file=str(yml_file), error=str(e))
    return rules

@router.get("/{rule_id}")
async def get_sigma_rule(rule_id: str, claims: dict = Depends(require_analyst)):
    """Get a specific Sigma rule by ID. Requires analyst role."""
    rule_file = find_rule_file(rule_id)
    if not rule_file:
        raise HTTPException(status_code=404, detail="Sigma rule not found")
        
    try:
        with open(rule_file, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/")
async def create_sigma_rule(rule: SigmaRuleRequest, request: Request, claims: dict = Depends(require_admin)):
    """Create a new Sigma rule. Admin only."""
    AuditLogger.log("sigma_rule_created", request=request, claims=claims, target=rule.id)
    if find_rule_file(rule.id):
        raise HTTPException(status_code=400, detail="Sigma rule with this ID already exists")
        
    ensure_rules_dir()
    # Save as rule_id.yml
    # Only alphanumeric and hyphens for filename to be safe
    safe_name = "".join([c if c.isalnum() or c == "-" else "_" for c in rule.id])
    file_path = RULES_DIR / f"{safe_name}.yml"
    
    data = rule.model_dump()
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False)
        logger.info("sigma_rule_created", rule_id=rule.id, file=str(file_path))
        return {"status": "success", "message": "Sigma rule created successfully", "rule": data}
    except Exception as e:
        logger.error("failed_to_create_rule", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to write rule file: {e}")

@router.put("/{rule_id}")
async def update_sigma_rule(rule_id: str, rule: SigmaRuleRequest, request: Request, claims: dict = Depends(require_admin)):
    """Update an existing Sigma rule. Admin only."""
    AuditLogger.log("sigma_rule_updated", request=request, claims=claims, target=rule_id)
    if rule_id != rule.id:
        raise HTTPException(status_code=400, detail="Path rule_id must match body rule.id")
        
    rule_file = find_rule_file(rule_id)
    if not rule_file:
        raise HTTPException(status_code=404, detail="Sigma rule not found")
        
    data = rule.model_dump()
    try:
        with open(rule_file, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, sort_keys=False)
        logger.info("sigma_rule_updated", rule_id=rule.id, file=str(rule_file))
        return {"status": "success", "message": "Sigma rule updated successfully", "rule": data}
    except Exception as e:
        logger.error("failed_to_update_rule", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to write rule file: {e}")

@router.delete("/{rule_id}")
async def delete_sigma_rule(rule_id: str, request: Request, claims: dict = Depends(require_admin)):
    """Delete a Sigma rule. Admin only."""
    AuditLogger.log("sigma_rule_deleted", request=request, claims=claims, target=rule_id)
    rule_file = find_rule_file(rule_id)
    if not rule_file:
        raise HTTPException(status_code=404, detail="Sigma rule not found")
        
    try:
        os.remove(rule_file)
        logger.info("sigma_rule_deleted", rule_id=rule_id, file=str(rule_file))
        return {"status": "success", "message": "Sigma rule deleted successfully"}
    except Exception as e:
        logger.error("failed_to_delete_rule", error=str(e))
        raise HTTPException(status_code=500, detail=f"Failed to delete rule file: {e}")


# ── Addendum A1: Export / Import / Coverage ──────────────────────────────────


@router.get("/export", response_class=StreamingResponse)
async def export_sigma_rules(
    claims: dict = Depends(require_analyst),
):
    """Export all Sigma rules as a ZIP archive.

    Returns application/zip with Content-Disposition: attachment.
    Uses stdlib zipfile + BytesIO — no extra dependencies.
    """
    ensure_rules_dir()

    buf = io.BytesIO()
    rule_count = 0

    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for yml_file in RULES_DIR.glob("*.yml"):
            try:
                zf.write(yml_file, arcname=yml_file.name)
                rule_count += 1
            except Exception as exc:
                logger.warning("export_skip_file", file=str(yml_file), error=str(exc))

    if rule_count == 0:
        raise HTTPException(status_code=404, detail="No Sigma rules found to export")

    buf.seek(0)

    def _iter_zip():
        yield buf.read()

    logger.info("sigma_rules_exported", rule_count=rule_count)
    return StreamingResponse(
        _iter_zip(),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=umbrix-sigma-rules.zip"},
    )


@router.post("/import")
async def import_sigma_rules(
    request: Request,
    file: UploadFile = File(...),
    overwrite: bool = False,
    claims: dict = Depends(require_admin),
):
    """Import Sigma rules from a ZIP archive or single YAML file.

    - ZIP: extracts all .yml files, validates YAML structure, writes to rules dir.
    - YAML: writes single rule file.

    Set ``overwrite=true`` to replace existing rules with the same ID.
    Requires admin role.
    """
    AuditLogger.log("sigma_rules_import_started", request=request, claims=claims)
    ensure_rules_dir()

    content = await file.read()
    filename = (file.filename or "").lower()

    imported: list[str] = []
    skipped: list[str] = []
    errors: list[str] = []

    def _write_rule(rule_data: dict, source_name: str) -> None:
        rule_id = rule_data.get("id")
        if not rule_id:
            errors.append(f"{source_name}: missing 'id' field")
            return
        safe_name = "".join([c if c.isalnum() or c == "-" else "_" for c in str(rule_id)])
        dest = RULES_DIR / f"{safe_name}.yml"
        if dest.exists() and not overwrite:
            skipped.append(rule_id)
            return
        try:
            with open(dest, "w", encoding="utf-8") as f:
                yaml.safe_dump(rule_data, f, sort_keys=False)
            imported.append(rule_id)
        except Exception as exc:
            errors.append(f"{rule_id}: {exc}")

    if filename.endswith(".zip"):
        try:
            buf = io.BytesIO(content)
            with zipfile.ZipFile(buf, "r") as zf:
                for name in zf.namelist():
                    if not name.lower().endswith(".yml"):
                        continue
                    try:
                        raw = zf.read(name).decode("utf-8")
                        parsed = yaml.safe_load(raw)
                        if not isinstance(parsed, dict):
                            errors.append(f"{name}: not a valid YAML dict")
                            continue
                        _write_rule(parsed, name)
                    except Exception as exc:
                        errors.append(f"{name}: {exc}")
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="Invalid ZIP file")
    elif filename.endswith(".yml") or filename.endswith(".yaml"):
        try:
            parsed = yaml.safe_load(content.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise HTTPException(status_code=400, detail="Not a valid YAML dict")
            _write_rule(parsed, filename)
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="File is not valid UTF-8")
    else:
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type. Upload a .zip or .yml file.",
        )

    logger.info("sigma_rules_imported", imported=len(imported), skipped=len(skipped), errors=len(errors))
    return {
        "status": "completed",
        "imported": imported,
        "skipped": skipped,
        "errors": errors,
    }


@router.get("/coverage")
async def sigma_coverage(
    claims: dict = Depends(require_analyst),
):
    """ATT&CK coverage summary derived from active Sigma rules.

    Lightweight endpoint for the Sigma Rules page stats widget.
    Returns just the summary block from the full MITRE coverage computation.
    For the full per-tactic breakdown, see GET /compliance/mitre-coverage.
    """
    import asyncio
    from app.services.mitre_coverage import compute_coverage

    loop = asyncio.get_event_loop()
    full = await loop.run_in_executor(None, compute_coverage)
    return {
        "summary": full["summary"],
        "tactic_coverage": {
            ta_id: {
                "name": tactic_data["name"],
                "technique_count": len(tactic_data["techniques"]),
            }
            for ta_id, tactic_data in full["by_tactic"].items()
            if tactic_data["techniques"]
        },
    }

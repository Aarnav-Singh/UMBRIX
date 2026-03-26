import json
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, ValidationError
from .ocsf_mapper import OCSFMapper

class ServiceInfo(BaseModel):
    actionType: str = Field(default="Unknown")
    eventFirstSeen: str
    eventLastSeen: str

class GuardDutyFinding(BaseModel):
    id: str = Field(default="Unknown")
    arn: str = Field(default="Unknown")
    type: str = Field(default="Unknown")
    title: str = Field(default="Unknown Finding")
    description: str = Field(default="")
    severity: float = Field(default=1.0)
    createdAt: str
    updatedAt: str
    service: ServiceInfo = Field(default_factory=dict)
    accountId: str = Field(default="Unknown")
    region: str = Field(default="Unknown")

class AWSGuardDutyParser:
    """Parses AWS GuardDuty findings and maps them to OCSF Security Finding."""

    @staticmethod
    def parse(log_data: Dict[str, Any]) -> Optional[Dict[Any, Any]]:
        raw_log = json.dumps(log_data)
        try:
            finding = GuardDutyFinding(**log_data)
        except ValidationError as e:
            print(f"GuardDuty parsing failed: {e}")
            return None

        # GuardDuty severity is 1.0 to 10.0
        # OCSF: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal
        sev_val = 1
        if finding.severity >= 7.0:
            sev_val = 4
        elif finding.severity >= 4.0:
            sev_val = 3
        elif finding.severity >= 1.0:
            sev_val = 2

        if finding.severity >= 9.0:
            sev_val = 5

        data: Dict[str, Any] = {
            "timestamp": finding.createdAt,
            "message": finding.title,
            "rule_name": finding.type,
            "rule_id": finding.id,
            "description": finding.description,
            "severity": sev_val,
        }

        return OCSFMapper.map_to_ocsf_security_finding(data, raw_log)

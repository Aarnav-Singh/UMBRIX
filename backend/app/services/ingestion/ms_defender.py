import json
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, ValidationError
from .ocsf_mapper import OCSFMapper

class MachineInfo(BaseModel):
    id: str = Field(default="Unknown")
    computerDnsName: str = Field(default="Unknown")
    osPlatform: str = Field(default="Unknown")

class DefenderAlert(BaseModel):
    id: str = Field(default="Unknown")
    incidentId: int = Field(default=0)
    title: str = Field(default="Unknown Alert")
    description: str = Field(default="")
    severity: str = Field(default="Low")
    status: str = Field(default="New")
    category: str = Field(default="Unknown")
    alertCreationTime: str
    machineId: str = Field(default="Unknown")
    computerDnsName: str = Field(default="Unknown")

class MSDefenderParser:
    """Parses Microsoft Defender for Endpoint alerts and maps them to OCSF Security Finding."""

    @staticmethod
    def parse(log_data: Dict[str, Any]) -> Optional[Dict[Any, Any]]:
        raw_log = json.dumps(log_data)
        try:
            alert = DefenderAlert(**log_data)
        except ValidationError as e:
            print(f"MSDefender parsing failed: {e}")
            return None

        # Severity mapping
        sev_map = {"Informational": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
        sev_val = sev_map.get(alert.severity, 1)

        data: Dict[str, Any] = {
            "timestamp": alert.alertCreationTime,
            "message": alert.title,
            "rule_name": alert.title,
            "rule_id": alert.id,
            "description": alert.description,
            "hostname": alert.computerDnsName,
            "severity": sev_val
        }

        return OCSFMapper.map_to_ocsf_security_finding(data, raw_log)

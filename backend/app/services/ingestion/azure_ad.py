import json
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field, ValidationError
from .ocsf_mapper import OCSFMapper

class UserPrincipal(BaseModel):
    id: str = Field(default="Unknown")
    userPrincipalName: str = Field(default="Unknown")
    ipAddress: str = Field(default="Unknown")

class AzureADSignIn(BaseModel):
    id: str = Field(default="Unknown")
    createdDateTime: str
    userDisplayName: str = Field(default="Unknown")
    userPrincipalName: str = Field(default="Unknown")
    userId: str = Field(default="Unknown")
    appId: str = Field(default="Unknown")
    appDisplayName: str = Field(default="Unknown")
    ipAddress: str = Field(default="Unknown")
    status: Dict[str, Any] = Field(default_factory=dict)

class AzureADParser:
    """Parses Azure AD Sign-in logs and maps them to OCSF Authentication."""

    @staticmethod
    def parse(log_data: Dict[str, Any]) -> Optional[Dict[Any, Any]]:
        raw_log = json.dumps(log_data)
        try:
            signin = AzureADSignIn(**log_data)
        except ValidationError as e:
            print(f"AzureAD parsing failed: {e}")
            return None

        err_code = signin.status.get("errorCode", 0)
        status_text = "Success" if err_code == 0 else "Failure"
        sev_val = 1 if err_code == 0 else 3

        data: Dict[str, Any] = {
            "timestamp": signin.createdDateTime,
            "message": f"Sign-in to {signin.appDisplayName} - Code {err_code}",
            "user": signin.userPrincipalName,
            "source_ip": signin.ipAddress,
            "activity_id": 1,  # 1 = Logon
            "status": status_text,
            "severity": sev_val,
        }

        return OCSFMapper.map_to_ocsf_authentication(data, raw_log)

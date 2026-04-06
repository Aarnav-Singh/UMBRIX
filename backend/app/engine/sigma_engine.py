"""Sigma-like rule matching engine.

Provides embedded detection rules mapped to MITRE ATT&CK techniques.
Matches against CanonicalEvent fields: source_type, action, severity,
signature_id, message.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml
import structlog

from app.schemas.canonical_event import CanonicalEvent, MitreMapping

logger = structlog.get_logger(__name__)

# ─── Embedded Sigma Rules ────────────────────────────────────────
# Each rule is a dict with:
#   id, name, mitre_technique_id, mitre_technique_name, mitre_tactic,
#   conditions (field→pattern), severity, confidence
SIGMA_RULES = [
    {
        "id": "sigma-001",
        "name": "CobaltStrike Beacon Activity",
        "mitre_technique_id": "T1071.001",
        "mitre_technique_name": "Application Layer Protocol: Web Protocols",
        "mitre_tactic": "command-and-control",
        "conditions": {"message": r"(?i)cobalt\s*strike|beacon"},
        "confidence": 0.95,
    },
    {
        "id": "sigma-002",
        "name": "Brute Force Login Attempt",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "mitre_tactic": "credential-access",
        "conditions": {"action": "authenticate", "outcome_failure": True},
        "confidence": 0.7,
    },
    {
        "id": "sigma-003",
        "name": "Port Scan Detected",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "mitre_tactic": "discovery",
        "conditions": {"message": r"(?i)port\s*scan|nmap|masscan"},
        "confidence": 0.8,
    },
    {
        "id": "sigma-004",
        "name": "SQL Injection Attempt",
        "mitre_technique_id": "T1190",
        "mitre_technique_name": "Exploit Public-Facing Application",
        "mitre_tactic": "initial-access",
        "conditions": {"message": r"(?i)sql\s*injection|union\s+select|drop\s+table|1\s*=\s*1"},
        "confidence": 0.85,
    },
    {
        "id": "sigma-005",
        "name": "Lateral Movement via SMB",
        "mitre_technique_id": "T1021.002",
        "mitre_technique_name": "Remote Services: SMB/Windows Admin Shares",
        "mitre_tactic": "lateral-movement",
        "conditions": {"dst_port": 445, "action": "connect"},
        "confidence": 0.6,
    },
    {
        "id": "sigma-006",
        "name": "DNS Tunneling Activity",
        "mitre_technique_id": "T1071.004",
        "mitre_technique_name": "Application Layer Protocol: DNS",
        "mitre_tactic": "command-and-control",
        "conditions": {"message": r"(?i)dns\s*tunnel|iodine|dnscat"},
        "confidence": 0.9,
    },
    {
        "id": "sigma-007",
        "name": "PowerShell Empire Activity",
        "mitre_technique_id": "T1059.001",
        "mitre_technique_name": "Command and Scripting Interpreter: PowerShell",
        "mitre_tactic": "execution",
        "conditions": {"message": r"(?i)powershell.*empire|invoke-empire|stager"},
        "confidence": 0.9,
    },
    {
        "id": "sigma-008",
        "name": "Data Exfiltration via HTTP",
        "mitre_technique_id": "T1048.002",
        "mitre_technique_name": "Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
        "mitre_tactic": "exfiltration",
        "conditions": {"high_bytes_out": True},
        "confidence": 0.5,
    },
    {
        "id": "sigma-009",
        "name": "Ransomware Indicators",
        "mitre_technique_id": "T1486",
        "mitre_technique_name": "Data Encrypted for Impact",
        "mitre_tactic": "impact",
        "conditions": {"message": r"(?i)ransomware|encrypt.*files|\.locked|ransom\s*note"},
        "confidence": 0.95,
    },
    {
        "id": "sigma-010",
        "name": "Suspicious RDP Connection",
        "mitre_technique_id": "T1021.001",
        "mitre_technique_name": "Remote Services: Remote Desktop Protocol",
        "mitre_tactic": "lateral-movement",
        "conditions": {"dst_port": 3389},
        "confidence": 0.5,
    },
    {
        "id": "sigma-011",
        "name": "Credential Dumping Attempt",
        "mitre_technique_id": "T1003",
        "mitre_technique_name": "OS Credential Dumping",
        "mitre_tactic": "credential-access",
        "conditions": {"message": r"(?i)mimikatz|lsass|credential\s*dump|sekurlsa"},
        "confidence": 0.95,
    },
    {
        "id": "sigma-012",
        "name": "Suspicious Process Execution",
        "mitre_technique_id": "T1059",
        "mitre_technique_name": "Command and Scripting Interpreter",
        "mitre_tactic": "execution",
        "conditions": {"action": "execute", "severity_high": True},
        "confidence": 0.65,
    },
    {
        "id": "sigma-013",
        "name": "Malware C2 Communication",
        "mitre_technique_id": "T1071",
        "mitre_technique_name": "Application Layer Protocol",
        "mitre_tactic": "command-and-control",
        "conditions": {"message": r"(?i)malware|c2|command.and.control|trojan|rat"},
        "confidence": 0.85,
    },
    {
        "id": "sigma-014",
        "name": "Privilege Escalation Attempt",
        "mitre_technique_id": "T1068",
        "mitre_technique_name": "Exploitation for Privilege Escalation",
        "mitre_tactic": "privilege-escalation",
        "conditions": {"message": r"(?i)privilege\s*escalat|sudo|su\s+root|uac\s*bypass"},
        "confidence": 0.8,
    },
    {
        "id": "sigma-015",
        "name": "Phishing Link Click",
        "mitre_technique_id": "T1566.002",
        "mitre_technique_name": "Phishing: Spearphishing Link",
        "mitre_tactic": "initial-access",
        "conditions": {"message": r"(?i)phishing|suspicious.*link|credential.*harvest"},
        "confidence": 0.75,
    },
    {
        "id": "sigma-016",
        "name": "DDoS Flood Detected",
        "mitre_technique_id": "T1498",
        "mitre_technique_name": "Network Denial of Service",
        "mitre_tactic": "impact",
        "conditions": {"message": r"(?i)ddos|flood|syn\s*flood|amplification"},
        "confidence": 0.85,
    },
    {
        "id": "sigma-017",
        "name": "Web Shell Upload",
        "mitre_technique_id": "T1505.003",
        "mitre_technique_name": "Server Software Component: Web Shell",
        "mitre_tactic": "persistence",
        "conditions": {"message": r"(?i)web\s*shell|china\s*chopper|c99|r57"},
        "confidence": 0.9,
    },
    {
        "id": "sigma-018",
        "name": "Suspicious DNS Query",
        "mitre_technique_id": "T1071.004",
        "mitre_technique_name": "Application Layer Protocol: DNS",
        "mitre_tactic": "command-and-control",
        "conditions": {"message": r"(?i)suspicious.*dns|dga|domain\s*generation"},
        "confidence": 0.7,
    },
]


class SigmaEngine:
    """Embedded Sigma-like rule matching engine."""

    def __init__(self) -> None:
        self._rules = list(SIGMA_RULES)  # copy so we can append without mutating module-level list

        # Auto-load YAML rules from sigma_rules/ directory if it exists
        yaml_dir = Path(__file__).parent / "sigma_rules"
        if yaml_dir.is_dir():
            self.load_rules_from_directory(str(yaml_dir))

        logger.info("sigma_engine_loaded", rule_count=len(self._rules))

    def load_rules_from_directory(self, path: str) -> None:
        """Read .yml files from *path*, parse YAML, and append to self._rules.

        Each YAML file is expected to have:
            id, name, mitre (technique_id, technique_name, tactic),
            conditions, confidence
        The method flattens the ``mitre`` mapping to match the embedded
        dict format used internally.
        """
        rules_dir = Path(path)
        if not rules_dir.is_dir():
            logger.warning("sigma_rules_dir_not_found", path=path)
            return

        loaded = 0
        for yml_file in sorted(rules_dir.glob("*.yml")):
            try:
                raw = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
                if not raw or not isinstance(raw, dict):
                    logger.warning("sigma_yaml_empty_or_invalid", file=str(yml_file))
                    continue

                mitre = raw.get("mitre", {})
                rule = {
                    "id": raw["id"],
                    "name": raw["name"],
                    "mitre_technique_id": mitre.get("technique_id", ""),
                    "mitre_technique_name": mitre.get("technique_name", ""),
                    "mitre_tactic": mitre.get("tactic", ""),
                    "conditions": raw.get("conditions", {}),
                    "confidence": float(raw.get("confidence", 0.5)),
                }
                self._rules.append(rule)
                loaded += 1
            except Exception as exc:
                logger.warning("sigma_yaml_parse_error", file=str(yml_file), error=str(exc))

        if loaded:
            logger.info("sigma_yaml_rules_loaded", directory=path, count=loaded)

    def match(self, event: CanonicalEvent) -> list[dict]:
        """Match event against all Sigma rules.

        Returns list of matched rules with MITRE mappings.
        """
        matches = []

        event_message = (event.message or "").lower()
        event_action = event.action.value if event.action else ""
        event_severity = event.severity.value if event.severity else ""
        event_outcome = event.outcome.value if event.outcome else ""
        dst_port = event.network.dst_port if event.network else None
        bytes_out = event.network.bytes_out if event.network else 0

        for rule in self._rules:
            conditions = rule["conditions"]
            matched = True

            for field, pattern in conditions.items():
                if field == "message" and isinstance(pattern, str):
                    if not re.search(pattern, event_message, re.IGNORECASE):
                        matched = False
                        break
                elif field == "action":
                    if event_action != pattern:
                        matched = False
                        break
                elif field == "dst_port":
                    if dst_port != pattern:
                        matched = False
                        break
                elif field == "outcome_failure":
                    if event_outcome != "failure":
                        matched = False
                        break
                elif field == "severity_high":
                    if event_severity not in ("high", "critical"):
                        matched = False
                        break
                elif field == "high_bytes_out":
                    if bytes_out < 1_000_000:  # 1MB threshold
                        matched = False
                        break

            if matched:
                matches.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "mitre_technique_id": rule["mitre_technique_id"],
                    "mitre_technique_name": rule["mitre_technique_name"],
                    "mitre_tactic": rule["mitre_tactic"],
                    "confidence": rule["confidence"],
                })

        if matches:
            logger.info(
                "sigma_match",
                event_id=event.event_id,
                matched_rules=[m["rule_id"] for m in matches],
            )

        return matches

    def to_mitre_mappings(self, matches: list[dict]) -> list[MitreMapping]:
        """Convert match results to MitreMapping schema objects."""
        return [
            MitreMapping(
                technique_id=m["mitre_technique_id"],
                technique_name=m["mitre_technique_name"],
                tactic=m["mitre_tactic"],
                confidence=m["confidence"],
            )
            for m in matches
        ]

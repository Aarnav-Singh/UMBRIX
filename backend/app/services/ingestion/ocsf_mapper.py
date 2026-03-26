import json
from typing import Dict, Any
from datetime import datetime, timezone

class OCSFMapper:
    """Core mapper to convert specific log schemas into OCSF (Open Cybersecurity Schema Framework)."""

    @staticmethod
    def map_to_ocsf_authentication(data: Dict[Any, Any], raw_log: str) -> Dict[Any, Any]:
        """Maps an authentication event to OCSF Authentication (class_uid: 3002)."""
        return {
            "metadata": {
                "version": "1.0.0",
            },
            "class_uid": 3002,
            "class_name": "Authentication",
            "category_uid": 3,
            "category_name": "Identity & Access Management",
            "time": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "message": data.get("message", ""),
            "raw_data": raw_log,
            "user": {
                "name": data.get("user", "Unknown"),
                "domain": data.get("domain"),
            },
            "src_endpoint": {
                "ip": data.get("source_ip"),
            },
            "activity_id": data.get("activity_id", 0),  # 1=Logon, 2=Logoff
            "status": data.get("status", "Unknown"), # Success, Failure
            "severity_id": data.get("severity", 1),
        }

    @staticmethod
    def map_to_ocsf_network_activity(data: Dict[Any, Any], raw_log: str) -> Dict[Any, Any]:
        """Maps network traffic to OCSF Network Activity (class_uid: 4001)."""
        return {
            "metadata": {
                "version": "1.0.0",
            },
            "class_uid": 4001,
            "class_name": "Network Activity",
            "category_uid": 4,
            "category_name": "Network Activity",
            "time": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "message": data.get("message", ""),
            "raw_data": raw_log,
            "src_endpoint": {
                "ip": data.get("source_ip"),
                "port": data.get("source_port"),
            },
            "dst_endpoint": {
                "ip": data.get("destination_ip"),
                "port": data.get("destination_port"),
            },
            "connection_info": {
                "protocol_name": data.get("protocol"),
            },
            "severity_id": data.get("severity", 1),
        }

    @staticmethod
    def map_to_ocsf_security_finding(data: Dict[Any, Any], raw_log: str) -> Dict[Any, Any]:
        """Maps IDS/IPS/AV alerts to OCSF Security Finding (class_uid: 2001)."""
        return {
            "metadata": {"version": "1.0.0"},
            "class_uid": 2001,
            "class_name": "Security Finding",
            "category_uid": 2,
            "category_name": "Findings",
            "time": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "message": data.get("message", "Security Alert"),
            "raw_data": raw_log,
            "finding": {
                "title": data.get("rule_name", data.get("signature", "Unknown Finding")),
                "uid": data.get("rule_id", data.get("signature_id")),
                "desc": data.get("description"),
            },
            "src_endpoint": {
                "ip": data.get("source_ip"),
                "port": data.get("source_port"),
            },
            "dst_endpoint": {
                "ip": data.get("destination_ip"),
                "port": data.get("destination_port"),
            },
            "severity_id": data.get("severity", 1),
            "state_id": 1,  # New
        }

    @staticmethod
    def map_to_ocsf_process_activity(data: Dict[Any, Any], raw_log: str) -> Dict[Any, Any]:
        """Maps EDR process events to OCSF Process Activity (class_uid: 1007)."""
        return {
            "metadata": {"version": "1.0.0"},
            "class_uid": 1007,
            "class_name": "Process Activity",
            "category_uid": 1,
            "category_name": "System Activity",
            "time": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "message": data.get("message", "Process Event"),
            "raw_data": raw_log,
            "process": {
                "name": data.get("process_name"),
                "pid": data.get("process_id"),
                "cmd_line": data.get("command_line"),
                "file": {
                    "path": data.get("process_path"),
                    "hashes": [{"algorithm": "SHA-256", "value": data.get("hash")}] if data.get("hash") else []
                }
            },
            "actor": {
                "user": {"name": data.get("user", "Unknown")}
            },
            "device": {"hostname": data.get("hostname")},
            "activity_id": data.get("activity_id", 1),  # 1=Launch, 2=Terminate
            "severity_id": data.get("severity", 1),
        }

    @staticmethod
    def map_to_ocsf_file_activity(data: Dict[Any, Any], raw_log: str) -> Dict[Any, Any]:
        """Maps EDR file events to OCSF File Activity (class_uid: 1001)."""
        return {
            "metadata": {"version": "1.0.0"},
            "class_uid": 1001,
            "class_name": "File Activity",
            "category_uid": 1,
            "category_name": "System Activity",
            "time": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "message": data.get("message", "File Event"),
            "raw_data": raw_log,
            "file": {
                "name": data.get("file_name"),
                "path": data.get("file_path"),
                "hashes": [{"algorithm": "SHA-256", "value": data.get("hash")}] if data.get("hash") else []
            },
            "actor": {
                "user": {"name": data.get("user", "Unknown")},
                "process": {"name": data.get("process_name"), "pid": data.get("process_id")}
            },
            "device": {"hostname": data.get("hostname")},
            "activity_id": data.get("activity_id", 1),  # 1=Create, 2=Read, 3=Update, 4=Delete
            "severity_id": data.get("severity", 1),
        }

    @staticmethod
    def map_to_ocsf_dns_activity(data: Dict[Any, Any], raw_log: str) -> Dict[Any, Any]:
        """Maps DNS requests to OCSF DNS Activity (class_uid: 4003)."""
        return {
            "metadata": {"version": "1.0.0"},
            "class_uid": 4003,
            "class_name": "DNS Activity",
            "category_uid": 4,
            "category_name": "Network Activity",
            "time": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "message": data.get("message", "DNS Query"),
            "raw_data": raw_log,
            "query": {
                "hostname": data.get("query"),
                "type": data.get("query_type", "A")
            },
            "answers": [{"data": ans} for ans in data.get("answers", [])],
            "src_endpoint": {
                "ip": data.get("source_ip"),
            },
            "dst_endpoint": {
                "ip": data.get("destination_ip"),
            },
            "activity_id": 1 if data.get("query") else 2,  # 1=Query, 2=Response
            "status": "Success" if data.get("rcode", 0) == 0 else "Failure",
            "severity_id": data.get("severity", 1),
        }

    @staticmethod
    def map_to_ocsf_http_activity(data: Dict[Any, Any], raw_log: str) -> Dict[Any, Any]:
        """Maps HTTP traffic to OCSF HTTP Activity (class_uid: 4002)."""
        return {
            "metadata": {"version": "1.0.0"},
            "class_uid": 4002,
            "class_name": "HTTP Activity",
            "category_uid": 4,
            "category_name": "Network Activity",
            "time": data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            "message": data.get("message", "HTTP Request"),
            "raw_data": raw_log,
            "http_request": {
                "http_method": data.get("http_method", "GET"),
                "url": {"path": data.get("url", "/"), "hostname": data.get("hostname")},
                "user_agent": data.get("user_agent"),
            },
            "http_response": {
                "code": data.get("status_code", 200),
            },
            "src_endpoint": {
                "ip": data.get("source_ip"),
            },
            "dst_endpoint": {
                "ip": data.get("destination_ip"),
                "port": data.get("destination_port", 80),
            },
            "severity_id": data.get("severity", 1),
        }

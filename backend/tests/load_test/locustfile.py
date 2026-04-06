"""UMBRIX — Load Testing with Locust.

Targets:
  - Event ingestion throughput (Suricata, Zeek, Syslog)
  - SOAR playbook execution latency
  - Health endpoint response time
  - Auth login under pressure

Usage:
  pip install locust
  locust -f tests/load_test/locustfile.py --host http://localhost:8000
"""
import random
import uuid
from locust import HttpUser, task, between


class SentinelAnalystUser(HttpUser):
    """Simulates an analyst interacting with the platform."""
    wait_time = between(0.5, 2)
    token: str = ""

    def on_start(self):
        """Login to get a JWT token."""
        resp = self.client.post("/api/v1/auth/login", json={
            "username": "admin",
            "password": "admin",
        })
        if resp.status_code == 200:
            self.token = resp.json().get("access_token", "")
        else:
            self.token = "invalid"

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    @task(5)
    def ingest_suricata_events(self):
        """High-frequency: Simulate Suricata alert ingestion."""
        events = [
            {
                "timestamp": "2026-03-27T00:00:00Z",
                "event_type": "alert",
                "src_ip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "src_port": random.randint(1024, 65535),
                "dest_ip": f"10.0.{random.randint(0, 10)}.{random.randint(1, 254)}",
                "dest_port": random.choice([22, 80, 443, 3389, 8080]),
                "alert": {
                    "action": "allowed",
                    "signature": f"ET SCAN Potential SSH Scan {uuid.uuid4().hex[:8]}",
                    "category": "Attempted Information Leak",
                    "severity": random.randint(1, 4),
                },
            }
        ]
        self.client.post(
            "/api/v1/ingest/suricata",
            json=events,
            headers=self._headers(),
            name="/api/v1/ingest/suricata",
        )

    @task(3)
    def ingest_syslog_events(self):
        """Medium-frequency: Simulate syslog ingestion."""
        events = [
            {
                "timestamp": "2026-03-27T00:00:00Z",
                "facility": random.choice(["auth", "kern", "daemon"]),
                "severity": random.randint(0, 7),
                "hostname": f"host-{random.randint(1, 50)}",
                "message": f"Failed password for root from 10.0.{random.randint(0,5)}.{random.randint(1,254)} port {random.randint(1024,65535)} ssh2",
            }
        ]
        self.client.post(
            "/api/v1/ingest/syslog",
            json=events,
            headers=self._headers(),
            name="/api/v1/ingest/syslog",
        )

    @task(2)
    def get_health(self):
        """Check system health."""
        self.client.get("/api/v1/health", name="/api/v1/health")

    @task(1)
    def get_posture(self):
        """Fetch security posture dashboard."""
        self.client.get(
            "/api/v1/posture/dashboard",
            headers=self._headers(),
            name="/api/v1/posture/dashboard",
        )

    @task(1)
    def list_playbooks(self):
        """List available SOAR playbooks."""
        self.client.get(
            "/api/v1/soar/playbooks",
            headers=self._headers(),
            name="/api/v1/soar/playbooks",
        )

    @task(1)
    def list_findings(self):
        """Query recent findings."""
        self.client.get(
            "/api/v1/findings?limit=20",
            headers=self._headers(),
            name="/api/v1/findings",
        )

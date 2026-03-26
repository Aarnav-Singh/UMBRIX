"""MITRE ATT&CK Threat Hunting Templates.

A collection of parameterized ClickHouse queries for proactive threat hunting.
Executed periodically by the ThreatHuntingAgent.
"""
from dataclasses import dataclass

@dataclass
class HuntTemplate:
    id: str
    name: str
    tactic: str
    description: str
    query: str
    confidence: str = "medium"

HUNT_TEMPLATES = [
    HuntTemplate(
        id="HUNT-001",
        name="Impossible Travel (T1078)",
        tactic="T1078",
        description="Same user authenticating from geographically distant locations within 2 hours.",
        query="""
            SELECT 
                user_id,
                count(DISTINCT geo_country) as unique_countries,
                groupArray(geo_country) as countries,
                min(timestamp) as first_seen,
                max(timestamp) as last_seen
            FROM events
            WHERE action = 'login' AND status = 'success'
              AND timestamp >= now() - INTERVAL 12 HOUR
            GROUP BY user_id
            HAVING unique_countries > 1
               AND dateDiff('hour', first_seen, last_seen) <= 2
        """
    ),
    HuntTemplate(
        id="HUNT-002",
        name="Brute Force Progression (T1110)",
        tactic="T1110",
        description="Multiple auth failures followed by a success from the same source IP.",
        query="""
            SELECT 
                src_ip,
                countIf(status = 'failure') as failures,
                countIf(status = 'success') as successes,
                groupArrayIf(user_id, status = 'success') as compromised_users
            FROM events
            WHERE action = 'login'
              AND timestamp >= now() - INTERVAL 6 HOUR
            GROUP BY src_ip
            HAVING failures > 5 AND successes > 0
        """,
        confidence="high"
    ),
    HuntTemplate(
        id="HUNT-003",
        name="Lateral Movement via SMB (T1021.002)",
        tactic="T1021.002",
        description="A single source IP connecting to multiple internal destinations over port 445.",
        query="""
            SELECT 
                src_ip,
                count(DISTINCT dst_ip) as unique_destinations,
                sum(bytes_out) as total_bytes
            FROM events
            WHERE dst_port = 445
              AND is_internal(src_ip) AND is_internal(dst_ip)
              AND timestamp >= now() - INTERVAL 6 HOUR
            GROUP BY src_ip
            HAVING unique_destinations >= 5
        """
    ),
    HuntTemplate(
        id="HUNT-004",
        name="Exfiltration via HTTP (T1041)",
        tactic="T1041",
        description="High volume outbound data transfer over HTTP/HTTPS to a single external IP.",
        query="""
            SELECT 
                src_ip,
                dst_ip,
                sum(bytes_out) as total_outbound_bytes
            FROM events
            WHERE dst_port IN (80, 443)
              AND is_internal(src_ip) AND NOT is_internal(dst_ip)
              AND timestamp >= now() - INTERVAL 24 HOUR
            GROUP BY src_ip, dst_ip
            HAVING total_outbound_bytes > 10485760  -- >10MB
        """
    ),
    HuntTemplate(
        id="HUNT-005",
        name="C2 Beaconing Pattern (T1071.001)",
        tactic="T1071.001",
        description="Regular interval connections to an external IP indicating potential C2 beaconing.",
        query="""
            SELECT 
                src_ip,
                dst_ip,
                count(*) as connection_count,
                avg(dateDiff('second', timestamp, now())) as avg_interval_sec
            FROM events
            WHERE dst_port IN (80, 443)
              AND is_internal(src_ip) AND NOT is_internal(dst_ip)
              AND timestamp >= now() - INTERVAL 6 HOUR
            GROUP BY src_ip, dst_ip
            HAVING connection_count > 50
        """
    ),
    HuntTemplate(
        id="HUNT-006",
        name="Credential Dumping (T1003)",
        tactic="T1003",
        description="Process access patterns targeting lsass.exe.",
        query="""
            SELECT 
                hostname,
                process_name,
                count(*) as access_count
            FROM events
            WHERE action = 'process_access'
              AND target_process = 'lsass.exe'
              AND timestamp >= now() - INTERVAL 24 HOUR
            GROUP BY hostname, process_name
            HAVING access_count > 0
        """,
        confidence="high"
    ),
    HuntTemplate(
        id="HUNT-007",
        name="Scheduled Task Persistence (T1053)",
        tactic="T1053",
        description="Creation of new scheduled tasks often used for persistence.",
        query="""
            SELECT 
                hostname,
                process_name,
                command_line
            FROM events
            WHERE action = 'process_creation'
              AND (process_name ILIKE '%schtasks.exe%' OR command_line ILIKE '%Register-ScheduledTask%')
              AND timestamp >= now() - INTERVAL 12 HOUR
            GROUP BY hostname, process_name, command_line
        """
    ),
    HuntTemplate(
        id="HUNT-008",
        name="Phishing Link Click (T1566)",
        tactic="T1566",
        description="Suspicious HTTP referrer chain from email clients to external domains.",
        query="""
            SELECT 
                src_ip,
                url,
                http_referrer,
                count(*) as clicks
            FROM events
            WHERE 
              (http_referrer ILIKE '%mail%' OR http_referrer ILIKE '%outlook%')
              AND timestamp >= now() - INTERVAL 24 HOUR
            GROUP BY src_ip, url, http_referrer
            HAVING clicks > 0
        """
    ),
]

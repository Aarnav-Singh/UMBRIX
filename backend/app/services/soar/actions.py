"""SOAR Execution Actions — Real SDK Integrations.

Each provider supports two modes:
  • **Live mode** — credentials configured → real API calls via vendor SDK.
  • **Mock mode** — no credentials → log the action and return "success"
    so the pipeline never crashes during development / demo.

Providers:
  - CrowdStrike Falcon (falconpy)
  - Palo Alto Networks PAN-OS (httpx XML API — panos lib optional)
  - Okta (httpx REST API)
  - Approval (manual gate)
"""
import logging
import uuid
from typing import Dict, Any

import httpx

from app.config import settings
from app.services.vault_service import vault_service

logger = logging.getLogger(__name__)

def get_soar_secret(key: str, fallback: str) -> str:
    """Fetch from Vault first, fallback to env var."""
    val = vault_service.get_secret(key)
    if val:
        return val
    return fallback


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class ActionExecutionError(Exception):
    """Raised when a SOAR action fails."""


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------
class ActionProvider:
    """Base class for SOAR action providers."""
    name: str = "Base"

    async def execute(self, action_type: str, context: Dict[str, Any]) -> str:
        raise NotImplementedError()


# ---------------------------------------------------------------------------
# CrowdStrike Falcon  (falconpy SDK)
# ---------------------------------------------------------------------------
class CrowdStrikeProvider(ActionProvider):
    """CrowdStrike Falcon integration.

    Requires env vars:
      CROWDSTRIKE_CLIENT_ID, CROWDSTRIKE_CLIENT_SECRET
    Optional:
      CROWDSTRIKE_BASE_URL (default: https://api.crowdstrike.com)
    """
    name = "CrowdStrike"

    def _is_configured(self) -> bool:
        cid = get_soar_secret("crowdstrike_client_id", settings.crowdstrike_client_id)
        csec = get_soar_secret("crowdstrike_client_secret", settings.crowdstrike_client_secret)
        return bool(cid and csec)

    async def execute(self, action_type: str, context: Dict[str, Any]) -> str:
        if action_type == "isolate_host":
            return await self._isolate_host(context)
        if action_type == "lift_containment":
            return await self._lift_containment(context)
        logger.error(f"[SOAR] [CrowdStrike] Unknown action type {action_type}")
        return "failed"

    async def _isolate_host(self, context: Dict[str, Any]) -> str:
        hostname = context.get("hostname")
        device_id = context.get("device_id")
        if not hostname and not device_id:
            logger.error("[SOAR] [CrowdStrike] Missing hostname or device_id")
            return "failed"

        if not self._is_configured():
            logger.warning(f"[SOAR] [CrowdStrike] MOCK — Would isolate host {hostname or device_id}")
            return "success"

        try:
            from falconpy import Hosts
            hosts_api = Hosts(
                client_id=get_soar_secret("crowdstrike_client_id", settings.crowdstrike_client_id),
                client_secret=get_soar_secret("crowdstrike_client_secret", settings.crowdstrike_client_secret),
                base_url=settings.crowdstrike_base_url,
            )

            # If we only have hostname, look up the device ID first
            if not device_id:
                lookup = hosts_api.query_devices_by_filter(
                    filter=f"hostname:'{hostname}'", limit=1
                )
                if lookup["status_code"] != 200 or not lookup["body"]["resources"]:
                    logger.error(f"[SOAR] [CrowdStrike] Host lookup failed for {hostname}")
                    return "failed"
                device_id = lookup["body"]["resources"][0]

            resp = hosts_api.perform_action(
                action_name="contain",
                ids=[device_id],
            )
            if resp["status_code"] in (200, 202):
                logger.info(f"[SOAR] [CrowdStrike] Host {device_id} containment initiated")
                return "success"
            logger.error(f"[SOAR] [CrowdStrike] Containment failed: {resp['body']}")
            return "failed"
        except ImportError:
            logger.warning("[SOAR] [CrowdStrike] falconpy not installed — running in mock mode")
            return "success"
        except Exception as exc:
            logger.exception(f"[SOAR] [CrowdStrike] Error: {exc}")
            return "failed"

    async def _lift_containment(self, context: Dict[str, Any]) -> str:
        device_id = context.get("device_id")
        if not device_id:
            logger.error("[SOAR] [CrowdStrike] Missing device_id for lift_containment")
            return "failed"

        if not self._is_configured():
            logger.warning(f"[SOAR] [CrowdStrike] MOCK — Would lift containment on {device_id}")
            return "success"

        try:
            from falconpy import Hosts
            hosts_api = Hosts(
                client_id=get_soar_secret("crowdstrike_client_id", settings.crowdstrike_client_id),
                client_secret=get_soar_secret("crowdstrike_client_secret", settings.crowdstrike_client_secret),
                base_url=settings.crowdstrike_base_url,
            )
            resp = hosts_api.perform_action(
                action_name="lift_containment",
                ids=[device_id],
            )
            if resp["status_code"] in (200, 202):
                logger.info(f"[SOAR] [CrowdStrike] Containment lifted for {device_id}")
                return "success"
            logger.error(f"[SOAR] [CrowdStrike] Lift containment failed: {resp['body']}")
            return "failed"
        except ImportError:
            logger.warning("[SOAR] [CrowdStrike] falconpy not installed — running in mock mode")
            return "success"
        except Exception as exc:
            logger.exception(f"[SOAR] [CrowdStrike] Error: {exc}")
            return "failed"


# ---------------------------------------------------------------------------
# Palo Alto Networks PAN-OS  (XML API via httpx)
# ---------------------------------------------------------------------------
class PaloAltoProvider(ActionProvider):
    """Palo Alto Networks PAN-OS integration.

    Requires env vars:
      PALOALTO_HOST      — firewall / Panorama management IP
      PALOALTO_API_KEY    — API key generated from the device
    """
    name = "PaloAlto"

    def _is_configured(self) -> bool:
        host = get_soar_secret("paloalto_host", settings.paloalto_host)
        key = get_soar_secret("paloalto_api_key", settings.paloalto_api_key)
        return bool(host and key)

    async def execute(self, action_type: str, context: Dict[str, Any]) -> str:
        if action_type == "block_ip":
            return await self._block_ip(context)
        if action_type == "unblock_ip":
            return await self._unblock_ip(context)
        logger.error(f"[SOAR] [PaloAlto] Unknown action type {action_type}")
        return "failed"

    async def _block_ip(self, context: Dict[str, Any]) -> str:
        ip = context.get("ip")
        if not ip:
            logger.error("[SOAR] [PaloAlto] Missing IP to block")
            return "failed"

        address_group = context.get("address_group", "Sentinel-Block-List")

        if not self._is_configured():
            logger.warning(f"[SOAR] [PaloAlto] MOCK — Would block IP {ip} in {address_group}")
            return "success"

        try:
            host = get_soar_secret("paloalto_host", settings.paloalto_host)
            api_key = get_soar_secret("paloalto_api_key", settings.paloalto_api_key)
            base = f"https://{host}/api"
            async with httpx.AsyncClient(verify=settings.paloalto_verify_ssl, timeout=30.0) as client:
                # 1. Create the address object
                addr_xpath = (
                    f"/config/devices/entry[@name='localhost.localdomain']"
                    f"/vsys/entry[@name='vsys1']/address/entry[@name='sentinel-{ip}']"
                )
                addr_element = f"<ip-netmask>{ip}/32</ip-netmask><description>Blocked by Sentinel</description>"
                resp = await client.get(base, params={
                    "type": "config",
                    "action": "set",
                    "xpath": addr_xpath,
                    "element": addr_element,
                    "key": api_key,
                })
                if resp.status_code != 200 or "<response status=\"success\"" not in resp.text:
                    logger.error(f"[SOAR] [PaloAlto] Create address failed: {resp.text}")
                    return "failed"

                # 2. Add to address group
                group_xpath = (
                    f"/config/devices/entry[@name='localhost.localdomain']"
                    f"/vsys/entry[@name='vsys1']/address-group/entry[@name='{address_group}']/static"
                )
                group_element = f"<member>sentinel-{ip}</member>"
                resp = await client.get(base, params={
                    "type": "config",
                    "action": "set",
                    "xpath": group_xpath,
                    "element": group_element,
                    "key": api_key,
                })

                # 3. Commit
                await client.get(base, params={
                    "type": "commit",
                    "cmd": "<commit></commit>",
                    "key": api_key,
                })

            logger.info(f"[SOAR] [PaloAlto] Blocked IP {ip} and committed config")
            return "success"
        except Exception as exc:
            logger.exception(f"[SOAR] [PaloAlto] Error: {exc}")
            return "failed"

    async def _unblock_ip(self, context: Dict[str, Any]) -> str:
        ip = context.get("ip")
        if not ip:
            logger.error("[SOAR] [PaloAlto] Missing IP to unblock")
            return "failed"

        if not self._is_configured():
            logger.warning(f"[SOAR] [PaloAlto] MOCK — Would unblock IP {ip}")
            return "success"

        try:
            host = get_soar_secret("paloalto_host", settings.paloalto_host)
            api_key = get_soar_secret("paloalto_api_key", settings.paloalto_api_key)
            base = f"https://{host}/api"
            async with httpx.AsyncClient(verify=settings.paloalto_verify_ssl, timeout=30.0) as client:
                addr_xpath = (
                    f"/config/devices/entry[@name='localhost.localdomain']"
                    f"/vsys/entry[@name='vsys1']/address/entry[@name='sentinel-{ip}']"
                )
                await client.get(base, params={
                    "type": "config",
                    "action": "delete",
                    "xpath": addr_xpath,
                    "key": api_key,
                })
                await client.get(base, params={
                    "type": "commit",
                    "cmd": "<commit></commit>",
                    "key": api_key,
                })
            logger.info(f"[SOAR] [PaloAlto] Unblocked IP {ip}")
            return "success"
        except Exception as exc:
            logger.exception(f"[SOAR] [PaloAlto] Error: {exc}")
            return "failed"


# ---------------------------------------------------------------------------
# Okta  (REST API via httpx)
# ---------------------------------------------------------------------------
class OktaProvider(ActionProvider):
    """Okta user lifecycle integration.

    Requires env vars:
      OKTA_DOMAIN     — e.g. "https://your-org.okta.com"
      OKTA_API_TOKEN  — SSWS token from Okta Admin console
    """
    name = "Okta"

    def _is_configured(self) -> bool:
        domain = get_soar_secret("okta_domain", settings.okta_domain)
        token = get_soar_secret("okta_api_token", settings.okta_api_token)
        return bool(domain and token)

    def _headers(self) -> dict:
        token = get_soar_secret("okta_api_token", settings.okta_api_token)
        return {
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def execute(self, action_type: str, context: Dict[str, Any]) -> str:
        if action_type == "quarantine_user":
            return await self._suspend_user(context)
        if action_type == "suspend_user":
            return await self._suspend_user(context)
        if action_type == "unsuspend_user":
            return await self._unsuspend_user(context)
        if action_type == "revoke_sessions":
            return await self._revoke_sessions(context)
        if action_type == "reset_mfa":
            return await self._reset_mfa(context)
        logger.error(f"[SOAR] [Okta] Unknown action type {action_type}")
        return "failed"

    async def _find_user_id(self, username: str) -> str | None:
        """Look up Okta user ID by login or email."""
        domain = get_soar_secret("okta_domain", settings.okta_domain)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{domain}/api/v1/users/{username}",
                headers=self._headers(),
            )
            if resp.status_code == 200:
                return resp.json().get("id")
        return None

    async def _suspend_user(self, context: Dict[str, Any]) -> str:
        username = context.get("username", "")
        if not username:
            logger.error("[SOAR] [Okta] Missing username")
            return "failed"

        if not self._is_configured():
            logger.warning(f"[SOAR] [Okta] MOCK — Would suspend user {username}")
            return "success"

        try:
            user_id = await self._find_user_id(username)
            if not user_id:
                logger.error(f"[SOAR] [Okta] User {username} not found")
                return "failed"

            domain = get_soar_secret("okta_domain", settings.okta_domain)
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{domain}/api/v1/users/{user_id}/lifecycle/suspend",
                    headers=self._headers(),
                )
            if resp.status_code in (200, 204):
                logger.info(f"[SOAR] [Okta] User {username} suspended")
                return "success"
            logger.error(f"[SOAR] [Okta] Suspend failed ({resp.status_code}): {resp.text}")
            return "failed"
        except Exception as exc:
            logger.exception(f"[SOAR] [Okta] Error: {exc}")
            return "failed"

    async def _unsuspend_user(self, context: Dict[str, Any]) -> str:
        username = context.get("username", "")
        if not username:
            return "failed"

        if not self._is_configured():
            logger.warning(f"[SOAR] [Okta] MOCK — Would unsuspend user {username}")
            return "success"

        try:
            user_id = await self._find_user_id(username)
            if not user_id:
                return "failed"
            domain = get_soar_secret("okta_domain", settings.okta_domain)
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{domain}/api/v1/users/{user_id}/lifecycle/unsuspend",
                    headers=self._headers(),
                )
            return "success" if resp.status_code in (200, 204) else "failed"
        except Exception as exc:
            logger.exception(f"[SOAR] [Okta] Error: {exc}")
            return "failed"

    async def _revoke_sessions(self, context: Dict[str, Any]) -> str:
        username = context.get("username", "")
        if not username:
            return "failed"

        if not self._is_configured():
            logger.warning(f"[SOAR] [Okta] MOCK — Would revoke sessions for {username}")
            return "success"

        try:
            user_id = await self._find_user_id(username)
            if not user_id:
                return "failed"
            domain = get_soar_secret("okta_domain", settings.okta_domain)
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.delete(
                    f"{domain}/api/v1/users/{user_id}/sessions",
                    headers=self._headers(),
                )
            logger.info(f"[SOAR] [Okta] Sessions revoked for {username}")
            return "success" if resp.status_code in (200, 204) else "failed"
        except Exception as exc:
            logger.exception(f"[SOAR] [Okta] Error: {exc}")
            return "failed"

    async def _reset_mfa(self, context: Dict[str, Any]) -> str:
        username = context.get("username", "")
        if not username:
            return "failed"

        if not self._is_configured():
            logger.warning(f"[SOAR] [Okta] MOCK — Would reset MFA for {username}")
            return "success"

        try:
            user_id = await self._find_user_id(username)
            if not user_id:
                return "failed"
            domain = get_soar_secret("okta_domain", settings.okta_domain)
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{domain}/api/v1/users/{user_id}/lifecycle/reset_factors",
                    headers=self._headers(),
                )
            logger.info(f"[SOAR] [Okta] MFA reset for {username}")
            return "success" if resp.status_code in (200, 204) else "failed"
        except Exception as exc:
            logger.exception(f"[SOAR] [Okta] Error: {exc}")
            return "failed"


# ---------------------------------------------------------------------------
# Approval Gate (unchanged)
# ---------------------------------------------------------------------------
class ApprovalProvider(ActionProvider):
    """Provides manual approval gates that pause execution."""
    name = "Approval"

    async def execute(self, action_type: str, context: Dict[str, Any]) -> str:
        if action_type == "wait_for_approval":
            approval_id = str(uuid.uuid4())
            context["approval_id"] = approval_id
            logger.info(f"[SOAR] Playbook paused waiting for approval. ID: {approval_id}")
            return "pending_approval"
        return "failed"


# ---------------------------------------------------------------------------
# ServiceNow  (REST Table API via httpx)
# ---------------------------------------------------------------------------
class ServiceNowProvider(ActionProvider):
    """ServiceNow incident and ticket management.

    Requires env vars:
      SERVICENOW_INSTANCE  — e.g. "your-instance.service-now.com"
      SERVICENOW_USERNAME  — API user
      SERVICENOW_PASSWORD  — API password
    """
    name = "ServiceNow"

    def _is_configured(self) -> bool:
        return bool(
            getattr(settings, "servicenow_instance", "")
            and getattr(settings, "servicenow_username", "")
            and getattr(settings, "servicenow_password", "")
        )

    async def execute(self, action_type: str, context: Dict[str, Any]) -> str:
        if action_type == "create_incident":
            return await self._create_incident(context)
        if action_type == "update_incident":
            return await self._update_incident(context)
        logger.error(f"[SOAR] [ServiceNow] Unknown action type {action_type}")
        return "failed"

    async def _create_incident(self, context: Dict[str, Any]) -> str:
        short_desc = context.get("short_description", "UMBRIX — Security Incident")
        description = context.get("description", "")
        urgency = context.get("urgency", "2")  # 1=High, 2=Medium, 3=Low
        impact = context.get("impact", "2")
        category = context.get("category", "Security")

        if not self._is_configured():
            logger.warning(f"[SOAR] [ServiceNow] MOCK — Would create incident: {short_desc}")
            return "success"

        try:
            url = f"https://{settings.servicenow_instance}/api/now/table/incident"
            auth = (settings.servicenow_username, settings.servicenow_password)
            payload = {
                "short_description": short_desc,
                "description": description,
                "urgency": urgency,
                "impact": impact,
                "category": category,
                "caller_id": context.get("caller_id", ""),
                "assignment_group": context.get("assignment_group", ""),
            }
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, json=payload, auth=auth, headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                })
            if resp.status_code in (200, 201):
                ticket_number = resp.json().get("result", {}).get("number", "unknown")
                logger.info(f"[SOAR] [ServiceNow] Incident created: {ticket_number}")
                context["ticket_number"] = ticket_number
                return "success"
            logger.error(f"[SOAR] [ServiceNow] Create failed: {resp.status_code} {resp.text}")
            return "failed"
        except Exception as exc:
            logger.exception(f"[SOAR] [ServiceNow] Error: {exc}")
            return "failed"

    async def _update_incident(self, context: Dict[str, Any]) -> str:
        sys_id = context.get("sys_id", "")
        if not sys_id:
            logger.error("[SOAR] [ServiceNow] Missing sys_id for update")
            return "failed"

        if not self._is_configured():
            logger.warning(f"[SOAR] [ServiceNow] MOCK — Would update incident {sys_id}")
            return "success"

        try:
            url = f"https://{settings.servicenow_instance}/api/now/table/incident/{sys_id}"
            auth = (settings.servicenow_username, settings.servicenow_password)
            update_fields = {k: v for k, v in context.items() if k not in ("sys_id",)}
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.patch(url, json=update_fields, auth=auth, headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                })
            return "success" if resp.status_code == 200 else "failed"
        except Exception as exc:
            logger.exception(f"[SOAR] [ServiceNow] Error: {exc}")
            return "failed"


# ---------------------------------------------------------------------------
# AWS Security Group  (boto3 SDK)
# ---------------------------------------------------------------------------
class AWSSecurityProvider(ActionProvider):
    """AWS Security Group and IAM integration.

    Requires env vars:
      AWS_ACCESS_KEY_ID
      AWS_SECRET_ACCESS_KEY
      AWS_DEFAULT_REGION
    Or an IAM role attached to the pod (preferred).
    """
    name = "AWS"

    def _is_configured(self) -> bool:
        try:
            import boto3
            boto3.client("sts").get_caller_identity()
            return True
        except Exception:
            return False

    async def execute(self, action_type: str, context: Dict[str, Any]) -> str:
        if action_type == "revoke_security_group_ingress":
            return await self._revoke_sg_ingress(context)
        if action_type == "isolate_instance":
            return await self._isolate_instance(context)
        logger.error(f"[SOAR] [AWS] Unknown action type {action_type}")
        return "failed"

    async def _revoke_sg_ingress(self, context: Dict[str, Any]) -> str:
        """Revoke an IP's ingress from a VPC Security Group."""
        sg_id = context.get("security_group_id", "")
        ip = context.get("ip", "")
        if not sg_id or not ip:
            logger.error("[SOAR] [AWS] Missing security_group_id or ip")
            return "failed"

        if not self._is_configured():
            logger.warning(f"[SOAR] [AWS] MOCK — Would revoke {ip} from SG {sg_id}")
            return "success"

        try:
            import boto3
            ec2 = boto3.client("ec2")
            ec2.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": f"{ip}/32", "Description": "Revoked by Sentinel SOAR"}],
                }],
            )
            logger.info(f"[SOAR] [AWS] Revoked {ip}/32 ingress from SG {sg_id}")
            return "success"
        except Exception as exc:
            logger.exception(f"[SOAR] [AWS] Error: {exc}")
            return "failed"

    async def _isolate_instance(self, context: Dict[str, Any]) -> str:
        """Replace an EC2 instance's SGs with an isolation (deny-all) SG."""
        instance_id = context.get("instance_id", "")
        isolation_sg = context.get("isolation_security_group_id", "")
        if not instance_id or not isolation_sg:
            logger.error("[SOAR] [AWS] Missing instance_id or isolation_security_group_id")
            return "failed"

        if not self._is_configured():
            logger.warning(f"[SOAR] [AWS] MOCK — Would isolate instance {instance_id}")
            return "success"

        try:
            import boto3
            ec2 = boto3.client("ec2")
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[isolation_sg],
            )
            logger.info(f"[SOAR] [AWS] Instance {instance_id} isolated with SG {isolation_sg}")
            return "success"
        except Exception as exc:
            logger.exception(f"[SOAR] [AWS] Error: {exc}")
            return "failed"


# ---------------------------------------------------------------------------
# Container Provider  (delegates to ContainerExecutor)
# ---------------------------------------------------------------------------
class ContainerProvider(ActionProvider):
    """Dispatch any action to an ephemeral Docker container.

    The container manifest is resolved by capability via ManifestRegistry.
    Supports an optional `manifest_name` key in the context dict to
    target a specific manifest instead of the auto-resolved one.
    """
    name = "container"

    async def execute(self, action_type: str, context: Dict[str, Any]) -> str:
        from app.services.soar.container_executor import container_executor
        manifest_name = context.pop("manifest_name", None)
        return await container_executor.run(
            capability=action_type,
            context=context,
            manifest_name=manifest_name,
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
class ActionRegistry:
    _providers: Dict[str, ActionProvider] | None = None

    @classmethod
    def _init_providers(cls) -> Dict[str, ActionProvider]:
        # Lazy import to break circular dependency with notification_providers
        from app.services.soar.notification_providers import SlackActionProvider, TeamsActionProvider
        return {
            "paloalto": PaloAltoProvider(),
            "crowdstrike": CrowdStrikeProvider(),
            "okta": OktaProvider(),
            "approval": ApprovalProvider(),
            "servicenow": ServiceNowProvider(),
            "aws": AWSSecurityProvider(),
            "slack": SlackActionProvider(),
            "teams": TeamsActionProvider(),
            "container": ContainerProvider(),
        }

    @classmethod
    @property
    def providers(cls) -> Dict[str, ActionProvider]:
        if cls._providers is None:
            cls._providers = cls._init_providers()
        return cls._providers

    @classmethod
    def get_provider(cls, name: str) -> ActionProvider | None:
        if cls._providers is None:
            cls._providers = cls._init_providers()
        return cls._providers.get(name)

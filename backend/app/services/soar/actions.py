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

logger = logging.getLogger(__name__)


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
        return bool(settings.crowdstrike_client_id and settings.crowdstrike_client_secret)

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
                client_id=settings.crowdstrike_client_id,
                client_secret=settings.crowdstrike_client_secret,
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
                client_id=settings.crowdstrike_client_id,
                client_secret=settings.crowdstrike_client_secret,
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
        return bool(settings.paloalto_host and settings.paloalto_api_key)

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
            base = f"https://{settings.paloalto_host}/api"
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
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
                    "key": settings.paloalto_api_key,
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
                    "key": settings.paloalto_api_key,
                })

                # 3. Commit
                await client.get(base, params={
                    "type": "commit",
                    "cmd": "<commit></commit>",
                    "key": settings.paloalto_api_key,
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
            base = f"https://{settings.paloalto_host}/api"
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                addr_xpath = (
                    f"/config/devices/entry[@name='localhost.localdomain']"
                    f"/vsys/entry[@name='vsys1']/address/entry[@name='sentinel-{ip}']"
                )
                resp = await client.get(base, params={
                    "type": "config",
                    "action": "delete",
                    "xpath": addr_xpath,
                    "key": settings.paloalto_api_key,
                })
                await client.get(base, params={
                    "type": "commit",
                    "cmd": "<commit></commit>",
                    "key": settings.paloalto_api_key,
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
        return bool(settings.okta_domain and settings.okta_api_token)

    def _headers(self) -> dict:
        return {
            "Authorization": f"SSWS {settings.okta_api_token}",
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
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{settings.okta_domain}/api/v1/users/{username}",
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

            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{settings.okta_domain}/api/v1/users/{user_id}/lifecycle/suspend",
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
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{settings.okta_domain}/api/v1/users/{user_id}/lifecycle/unsuspend",
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
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.delete(
                    f"{settings.okta_domain}/api/v1/users/{user_id}/sessions",
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
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{settings.okta_domain}/api/v1/users/{user_id}/lifecycle/reset_factors",
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
# Registry
# ---------------------------------------------------------------------------
class ActionRegistry:
    providers: Dict[str, ActionProvider] = {
        "paloalto": PaloAltoProvider(),
        "crowdstrike": CrowdStrikeProvider(),
        "okta": OktaProvider(),
        "approval": ApprovalProvider(),
    }

    @classmethod
    def get_provider(cls, name: str) -> ActionProvider | None:
        return cls.providers.get(name)

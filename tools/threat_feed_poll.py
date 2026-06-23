"""
Threat Feed Poll Tool
Polls a threat intelligence feed and returns indicators.
"""

import sys
import os
import logging
import requests
import asyncio
from typing import Dict, Any, Optional
from plugin_interface import ToolPlugin

# Ensure agent/ is on sys.path so `from lib.integration_credentials import ...`
# works when the plugin is loaded via spec_from_file_location.
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.append(_parent_dir)

from lib.integration_credentials import (  # noqa: E402
    checkout_provider,
    reconcile_call,
    QuotaExceededError,
    IntegrationCredentialsError,
)

logger = logging.getLogger(__name__)


class ThreatFeedPollTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "threatintel:feed_poll"

    @property
    def description(self) -> str:
        return "Poll a threat intelligence feed (OTX, Abuse.ch, PhishTank, or custom) and return parsed indicators"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "feedType": {
                    "type": "string",
                    "enum": ["OTX", "ABUSE_CH", "PHISHTANK", "CUSTOM"],
                    "description": "Type of threat feed to poll"
                },
                "feedUrl": {
                    "type": "string",
                    "description": "URL of the threat feed to poll"
                },
                "apiKey": {
                    "type": "string",
                    "description": "Optional API key for authenticated feeds"
                }
            },
            "required": ["feedUrl"]
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "recon",
            "phase": 1,
            "domain": ["threat_intelligence"],
            "input_type": ["url"],
            "output_type": ["threat_indicators"],
            "chainable_after": [],
            "chainable_before": [],
        }

    def run(self, params: Dict[str, Any]) -> Dict[str, Any]:
        feed_type = params.get("feedType", "CUSTOM")
        feed_url = params.get("feedUrl", "")
        api_key = params.get("apiKey", "")

        if not feed_url:
            return {"success": False, "error": "feedUrl is required"}

        indicators = []
        headers = {}
        if api_key:
            headers["X-OTX-API-KEY"] = api_key

        try:
            if feed_type == "OTX":
                resp = requests.get(feed_url, headers=headers, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                for indicator in data.get("indicators", data.get("results", [])):
                    indicators.append({
                        "type": indicator.get("type", "unknown").upper(),
                        "value": indicator.get("indicator", ""),
                        "threatType": indicator.get("title", ""),
                        "confidence": indicator.get("confidence", 50),
                    })
            elif feed_type == "ABUSE_CH":
                resp = requests.get(feed_url, headers=headers, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                for entry in data.get("data", data.get("urls", [])):
                    indicators.append({
                        "type": "URL" if "url" in entry else "HASH",
                        "value": entry.get("url", entry.get("md5_hash", entry.get("sha256_hash", ""))),
                        "threatType": entry.get("threat", entry.get("threat_type", "")),
                        "confidence": 80,
                    })
            elif feed_type == "PHISHTANK":
                resp = requests.get(feed_url, headers=headers, timeout=60)
                resp.raise_for_status()
                data = resp.json()
                for entry in data[:1000]:
                    indicators.append({
                        "type": "URL",
                        "value": entry.get("url", ""),
                        "threatType": "phishing",
                        "confidence": 90 if entry.get("verified") == "yes" else 50,
                    })
            else:  # CUSTOM
                resp = requests.get(feed_url, headers=headers, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                if isinstance(data, list):
                    indicators = data[:1000]
                elif isinstance(data, dict) and "indicators" in data:
                    indicators = data["indicators"][:1000]

            return {
                "success": True,
                "output": {
                    "indicators": indicators,
                    "total_fetched": len(indicators),
                    "new_count": len(indicators),
                    "feed_type": feed_type,
                }
            }
        except Exception as e:
            return {"success": False, "error": str(e), "output": {"indicators": [], "total_fetched": 0}}

    async def execute(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute feed polling without blocking the agent event loop.

        DRP→ASM T2.8c: for the OTX feed type, we lease an OTX_API quota
        before calling the upstream and reconcile after. OTX is reached via
        TWO parallel paths in the agent codebase (this tool AND
        darkweb_monitor._query_otx) — each lease independently so the
        backend ledger sees the true call rate.

        Non-OTX feed types are public unauthenticated feeds without
        rate-limit concerns at our volumes and are NOT leased.
        """
        feed_type = (parameters.get("feedType") or "CUSTOM").upper()

        # Non-OTX feeds: no quota seam needed.
        if feed_type != "OTX":
            return await asyncio.to_thread(self.run, parameters)

        # OTX: lease a quota unit before the call.
        lease_token: Optional[str] = None
        try:
            lease = await checkout_provider('OTX_API', requested_units=1)
            # If an API key was supplied in parameters, the lease's key
            # supersedes only when the caller didn't override.
            if not parameters.get('apiKey') and lease.get('apiKey'):
                parameters = {**parameters, 'apiKey': lease['apiKey']}
            lease_token = lease.get('leaseToken')
        except QuotaExceededError as e:
            logger.warning(f"[threat_feed_poll] OTX quota exceeded: {e}")
            return {
                "success": False,
                "error": "quota_exceeded",
                "retryAfter": e.retry_after,
                "providerKey": "OTX_API",
                "output": {"indicators": [], "total_fetched": 0},
            }
        except IntegrationCredentialsError:
            # No integration configured; fall through to the existing
            # behaviour (apiKey from parameters or anonymous).
            pass

        # Lease is held — the reconcile MUST run on every exit path
        # (success, exception, cancellation) or the quota unit leaks and
        # accumulates toward a provider ban. Mirror the try/finally pattern
        # used by the vendor tools (hiker_brand.py ~346-366).
        result: Optional[Dict[str, Any]] = None
        try:
            result = await asyncio.to_thread(self.run, parameters)
            return result
        finally:
            # Reconcile the lease — best-effort, never raises. When run()
            # raised, `result` is None and the call is reconciled as a
            # failure so the lease is released rather than leaked.
            if lease_token:
                success = bool(result and result.get('success'))
                error_code = (
                    None
                    if success
                    else str((result or {}).get('error', 'tool_exception'))[:64]
                )
                await reconcile_call(
                    'OTX_API',
                    lease_token,
                    units=1,
                    success=success,
                    error_code=error_code,
                )

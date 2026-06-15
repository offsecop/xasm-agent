"""
Threat Feed Poll Tool
Polls a threat intelligence feed and returns indicators.
"""

import json
import requests
import asyncio
from typing import Dict, Any
from plugin_interface import ToolPlugin


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
        """Execute feed polling without blocking the agent event loop."""
        return await asyncio.to_thread(self.run, parameters)

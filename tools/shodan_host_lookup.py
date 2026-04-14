"""
Shodan Host Lookup Tool
Query Shodan for detailed information about an IP address
"""

import sys
import os
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.append(_parent_dir)

from plugin_interface import ToolPlugin
from lib.shodan_client import ShodanClient
from lib.ip_utils import is_private_ip, classify_ip
from lib.integration_credentials import get_shodan_api_key


class ShodanHostLookupTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "shodan:host_lookup"

    @property
    def description(self) -> str:
        return "Look up detailed information about an IP address using Shodan (services, banners, CVEs)"

    @property
    def schema(self):
        return {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "IP address to look up"
                },
                "apiKey": {
                    "type": "string",
                    "description": "Shodan API key (optional if configured in integration)"
                },
                "includeHistory": {
                    "type": "boolean",
                    "description": "Include historical banners (default: false)",
                    "default": False
                },
                "externalOnly": {
                    "type": "boolean",
                    "description": "Skip internal/private IPs (RFC 1918) to save API credits (default: true)",
                    "default": True
                }
            },
            "required": ["ip"]
        }

    @property
    def metadata(self):
        return {
            "category": "enrichment",
            "phase": 2,
            "domain": ["infra", "osint"],
            "input_type": ["ip"],
            "output_type": ["services", "findings"],
            "chainable_after": ["nmap:", "system:dns_resolve"],
            "chainable_before": ["nuclei:", "testssl:"],
        }

    async def execute(self, parameters: dict):
        """Execute Shodan host lookup"""
        ip = parameters.get("ip") or parameters.get("target")
        api_key = parameters.get("apiKey")
        include_history = parameters.get("includeHistory", False)
        external_only = parameters.get("externalOnly", True)

        if not ip:
            return {
                "success": False,
                "error": "IP address is required"
            }

        # Check if IP is internal (RFC 1918) and skip to save API credits
        if external_only and is_private_ip(ip):
            classification = classify_ip(ip)
            print(f"[Shodan] Skipping internal IP {ip} ({classification}) to preserve API credits")
            return {
                "success": True,
                "skipped": True,
                "reason": f"IP {ip} is classified as '{classification}' (internal/private). Shodan can only query external IPs.",
                "output": {
                    "ip": ip,
                    "classification": classification,
                    "is_internal": True,
                },
                "findings": [],
                "summary": {
                    "ip": ip,
                    "classification": classification,
                    "skipped": True,
                    "servicesFound": 0,
                    "cvesFound": 0,
                    "findingsGenerated": 0,
                }
            }

        if not api_key:
            # Try to get from environment or integration
            api_key = os.environ.get("SHODAN_API_KEY")

        if not api_key:
            # Try to fetch from backend integration
            print("[Shodan] Fetching API key from backend integration...")
            api_key = await get_shodan_api_key()

        if not api_key:
            return {
                "success": False,
                "error": "Shodan API key is required. Provide via apiKey parameter or enable agent access in Shodan integration."
            }

        try:
            print(f"[Shodan] Looking up IP: {ip}")
            client = ShodanClient(api_key, verify_ssl=False)

            # Get host information
            host_data = await client.get_host(ip, history=include_history)

            # Extract structured data
            services = client.extract_services(host_data)
            cves = client.extract_cves(host_data)

            print(f"[Shodan] Found {len(services)} services, {len(cves)} CVEs for {ip}")

            # Build output for ingestion
            output = {
                "ip": ip,
                "hostnames": host_data.get("hostnames", []),
                "org": host_data.get("org"),
                "isp": host_data.get("isp"),
                "asn": host_data.get("asn"),
                "os": host_data.get("os"),
                "ports": host_data.get("ports", []),
                "services": services,
                "cves": cves,
                "geolocation": {
                    "city": host_data.get("city"),
                    "country": host_data.get("country_name"),
                    "countryCode": host_data.get("country_code"),
                    "region": host_data.get("region_code"),
                    "latitude": host_data.get("latitude"),
                    "longitude": host_data.get("longitude"),
                },
                "lastUpdate": host_data.get("last_update"),
            }

            # Create findings from CVEs
            findings = []
            for cve in cves:
                severity = "INFO"
                if cve.get("cvss"):
                    cvss = cve["cvss"]
                    if cvss >= 9.0:
                        severity = "CRITICAL"
                    elif cvss >= 7.0:
                        severity = "HIGH"
                    elif cvss >= 4.0:
                        severity = "MEDIUM"
                    elif cvss >= 0.1:
                        severity = "LOW"

                findings.append({
                    "title": f"{cve['id']} detected on {ip}",
                    "description": cve.get("summary") or f"Vulnerability {cve['id']} detected by Shodan",
                    "severity": severity,
                    "sourceTool": "threatintel:shodan:host_lookup",
                    "vulnerabilityRef": cve["id"],
                    "primaryCve": cve["id"],
                    "cvss3Score": cve.get("cvss"),
                    "evidence": {
                        "ip": ip,
                        "port": cve.get("port"),
                        "verified": cve.get("verified", False),
                        "references": cve.get("references", []),
                        "source": "shodan",
                    },
                    "affectedResources": [{
                        "resourceType": "Asset",
                        "value": ip,
                        "assetType": "IP_ADDRESS",
                    }],
                })

            return {
                "success": True,
                "output": output,
                "findings": findings,
                "summary": {
                    "ip": ip,
                    "servicesFound": len(services),
                    "cvesFound": len(cves),
                    "findingsGenerated": len(findings),
                }
            }

        except ValueError as e:
            return {
                "success": False,
                "error": str(e)
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error querying Shodan: {str(e)}"
            }


def get_tool():
    return ShodanHostLookupTool()

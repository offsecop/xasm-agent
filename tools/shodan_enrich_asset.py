"""
Shodan Enrich Asset Tool
Enrich an existing asset with Shodan data
"""

import ipaddress
import sys
import os
from datetime import datetime
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.append(_parent_dir)

from plugin_interface import ToolPlugin
from lib.shodan_client import ShodanClient
from lib.ip_utils import is_private_ip, classify_ip
from lib.integration_credentials import get_shodan_api_key


class ShodanEnrichAssetTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "shodan:enrich_asset"

    @property
    def description(self) -> str:
        return "Enrich an asset with Shodan data (services, CVEs, metadata)"

    @property
    def schema(self):
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address or hostname to enrich"
                },
                "assetId": {
                    "type": "string",
                    "description": "Asset ID to enrich (alternative to target)"
                },
                "apiKey": {
                    "type": "string",
                    "description": "Shodan API key (optional if configured in integration)"
                },
                "externalOnly": {
                    "type": "boolean",
                    "description": "Skip internal/private IPs (RFC 1918) to save API credits (default: true)",
                    "default": True
                }
            },
            "oneOf": [
                {"required": ["target"]},
                {"required": ["assetId"]}
            ]
        }

    @property
    def metadata(self):
        return {
            "category": "enrichment",
            "phase": 2,
            "domain": ["infra", "osint"],
            "input_type": ["ip", "hostname"],
            "output_type": ["services", "findings"],
            "chainable_after": ["nmap:", "system:dns_resolve", "subfinder:"],
            "chainable_before": ["nuclei:", "testssl:"],
        }

    async def execute(self, parameters: dict):
        """Execute Shodan asset enrichment"""
        target = parameters.get("target")
        asset_id = parameters.get("assetId")
        api_key = parameters.get("apiKey")
        external_only = parameters.get("externalOnly", True)

        if not target and not asset_id:
            return {
                "success": False,
                "error": "Either target (IP/hostname) or assetId is required"
            }

        # Check if target IP is internal (RFC 1918) and skip to save API credits
        if external_only and target and self._is_ip(target) and is_private_ip(target):
            classification = classify_ip(target)
            print(f"[Shodan] Skipping internal IP {target} ({classification}) to preserve API credits")
            return {
                "success": True,
                "skipped": True,
                "reason": f"IP {target} is classified as '{classification}' (internal/private). Shodan can only query external IPs.",
                "output": {
                    "target": target,
                    "classification": classification,
                    "is_internal": True,
                },
                "findings": [],
                "summary": {
                    "target": target,
                    "classification": classification,
                    "skipped": True,
                    "servicesFound": 0,
                    "cvesFound": 0,
                    "findingsGenerated": 0,
                }
            }

        if not api_key:
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
            client = ShodanClient(api_key)
            ip_to_lookup = target

            # If target is a hostname, resolve it first
            if target and not self._is_ip(target):
                print(f"[Shodan] Resolving hostname: {target}")
                resolved = await client.dns_resolve([target])
                ip_to_lookup = resolved.get(target)
                if not ip_to_lookup:
                    return {
                        "success": False,
                        "error": f"Could not resolve hostname: {target}"
                    }
                print(f"[Shodan] Resolved {target} -> {ip_to_lookup}")

                # Check if resolved IP is internal
                if external_only and is_private_ip(ip_to_lookup):
                    classification = classify_ip(ip_to_lookup)
                    print(f"[Shodan] Resolved IP {ip_to_lookup} is internal ({classification}) - skipping")
                    return {
                        "success": True,
                        "skipped": True,
                        "reason": f"Hostname {target} resolves to internal IP {ip_to_lookup} ({classification}). Shodan can only query external IPs.",
                        "output": {
                            "target": target,
                            "resolvedIp": ip_to_lookup,
                            "classification": classification,
                            "is_internal": True,
                        },
                        "findings": [],
                        "summary": {
                            "target": target,
                            "resolvedIp": ip_to_lookup,
                            "classification": classification,
                            "skipped": True,
                            "servicesFound": 0,
                            "cvesFound": 0,
                            "findingsGenerated": 0,
                        }
                    }

            print(f"[Shodan] Enriching asset: {ip_to_lookup}")
            host_data = await client.get_host(ip_to_lookup)

            # Extract data
            services = client.extract_services(host_data)
            cves = client.extract_cves(host_data)

            print(f"[Shodan] Found {len(services)} services, {len(cves)} CVEs")

            # Build enrichment data
            enrichment = {
                "ip": ip_to_lookup,
                "hostnames": host_data.get("hostnames", []),
                "org": host_data.get("org"),
                "isp": host_data.get("isp"),
                "asn": host_data.get("asn"),
                "os": host_data.get("os"),
                "geolocation": {
                    "city": host_data.get("city"),
                    "country": host_data.get("country_name"),
                    "countryCode": host_data.get("country_code"),
                    "region": host_data.get("region_code"),
                    "latitude": host_data.get("latitude"),
                    "longitude": host_data.get("longitude"),
                },
                "lastUpdate": host_data.get("last_update"),
                "source": "shodan",
            }

            # Generate service records
            service_records = []
            for svc in services:
                service_records.append({
                    "port": svc["port"],
                    "protocol": svc["transport"],
                    "serviceName": svc.get("product"),
                    "softwareName": svc.get("product"),
                    "softwareVersion": svc.get("version"),
                    "banner": svc.get("banner"),
                    "ssl": svc.get("ssl", False),
                    "http": svc.get("http", False),
                })

            # Generate findings from CVEs
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
                    "title": f"{cve['id']} detected on {ip_to_lookup}",
                    "description": cve.get("summary") or f"Vulnerability {cve['id']} detected by Shodan",
                    "severity": severity,
                    "sourceTool": "threatintel:shodan:enrich_asset",
                    "vulnerabilityRef": cve["id"],
                    "primaryCve": cve["id"],
                    "cvss3Score": cve.get("cvss"),
                    "evidence": {
                        "ip": ip_to_lookup,
                        "port": cve.get("port"),
                        "verified": cve.get("verified", False),
                        "references": cve.get("references", []),
                        "source": "shodan",
                        "enrichedTarget": target,
                    },
                    "affectedResources": [{
                        "resourceType": "Asset",
                        "value": ip_to_lookup,
                        "assetType": "IP_ADDRESS",
                    }],
                })

            # Build asset update
            asset_update = {
                "type": "IP_ADDRESS",
                "value": ip_to_lookup,
                "metadata": {
                    "importSource": "shodan",
                    "shodanId": f"shodan-{ip_to_lookup}",
                    "hostnames": host_data.get("hostnames", []),
                    "org": host_data.get("org"),
                    "isp": host_data.get("isp"),
                    "asn": host_data.get("asn"),
                    "os": host_data.get("os"),
                    "geolocation": enrichment["geolocation"],
                    "shodanLastUpdate": host_data.get("last_update"),
                    "enrichedAt": datetime.utcnow().isoformat(),
                }
            }

            return {
                "success": True,
                "output": {
                    "enrichment": enrichment,
                    "services": service_records,
                    "cves": cves,
                },
                "asset": asset_update,
                "services": service_records,
                "findings": findings,
                "summary": {
                    "target": target or ip_to_lookup,
                    "resolvedIp": ip_to_lookup if target != ip_to_lookup else None,
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
                "error": f"Error enriching asset with Shodan: {str(e)}"
            }

    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address (IPv4 or IPv6)"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


def get_tool():
    return ShodanEnrichAssetTool()

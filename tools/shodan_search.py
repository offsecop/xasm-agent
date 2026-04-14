"""
Shodan Search Tool
Search Shodan for hosts matching a query
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


class ShodanSearchTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "shodan:search"

    @property
    def description(self) -> str:
        return "Search Shodan for hosts matching a query (e.g., org:\"Company\" or product:nginx)"

    @property
    def schema(self):
        return {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Shodan search query (e.g., org:\"Company\", product:nginx port:443)"
                },
                "target": {
                    "type": "string",
                    "description": "Target domain or IP — used to auto-build a Shodan query (hostname:<target> or net:<target>) when 'query' is not provided"
                },
                "apiKey": {
                    "type": "string",
                    "description": "Shodan API key (optional if configured in integration)"
                },
                "maxResults": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 100, max: 500)",
                    "default": 100
                },
                "createAssets": {
                    "type": "boolean",
                    "description": "Create assets from discovered hosts (default: true)",
                    "default": True
                },
                "filterInternal": {
                    "type": "boolean",
                    "description": "Filter out internal/private IPs from results (RFC 1918) (default: true)",
                    "default": True
                }
            },
            "required": []
        }

    def validate_parameters(self, parameters: dict) -> bool:
        """Accept either 'query' or 'target' as the search input."""
        if not parameters.get("query") and not parameters.get("target"):
            print(f"[Validate] shodan:search requires 'query' or 'target' parameter")
            return False
        return True

    @property
    def metadata(self):
        return {
            "category": "recon",
            "phase": 1,
            "domain": ["osint", "infra"],
            "input_type": ["query"],
            "output_type": ["ips", "services"],
            "chainable_after": [],
            "chainable_before": ["nmap:", "shodan:host_lookup"],
        }

    async def execute(self, parameters: dict):
        """Execute Shodan search"""
        query = parameters.get("query")
        target = parameters.get("target")
        api_key = parameters.get("apiKey")
        max_results = min(parameters.get("maxResults", 100), 500)
        create_assets = parameters.get("createAssets", True)
        filter_internal = parameters.get("filterInternal", True)

        # Auto-build query from target when query is not explicitly provided
        if not query and target:
            import re
            # Detect IP or CIDR — use net: filter; otherwise use hostname:
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}(\/\d+)?$', target):
                query = f"net:{target}"
            else:
                query = f"hostname:{target}"
            print(f"[Shodan] Auto-built query from target '{target}': {query}")

        if not query:
            return {
                "success": False,
                "error": "Search query is required (provide 'query' or 'target')"
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
            print(f"[Shodan] Searching: {query}")
            client = ShodanClient(api_key)

            # Get search count first (doesn't consume credits)
            count_result = await client.search_count(query)
            total_available = count_result.get("total", 0)
            print(f"[Shodan] Total matching hosts: {total_available}")

            # Fetch results (paginated)
            all_hosts = []
            skipped_internal_count = 0
            page = 1
            results_per_page = 100

            while len(all_hosts) < max_results:
                result = await client.search(query, page=page)
                matches = result.get("matches", [])

                if not matches:
                    break
                for match in matches:
                    if len(all_hosts) >= max_results:
                        break

                    # Deduplicate by IP
                    ip = match.get("ip_str")
                    if any(h["ip"] == ip for h in all_hosts):
                        continue

                    # Filter internal IPs if requested
                    if filter_internal and is_private_ip(ip):
                        skipped_internal_count += 1
                        continue

                    all_hosts.append({
                        "ip": ip,
                        "hostnames": match.get("hostnames", []),
                        "port": match.get("port"),
                        "org": match.get("org"),
                        "isp": match.get("isp"),
                        "asn": match.get("asn"),
                        "os": match.get("os"),
                        "product": match.get("product"),
                        "version": match.get("version"),
                        "geolocation": {
                            "city": match.get("location", {}).get("city"),
                            "country": match.get("location", {}).get("country_name"),
                            "countryCode": match.get("location", {}).get("country_code"),
                        },
                        "vulns": list(match.get("vulns", {}).keys()) if match.get("vulns") else [],
                        "timestamp": match.get("timestamp"),
                    })

                page += 1
                if len(matches) < results_per_page:
                    break

            print(f"[Shodan] Fetched {len(all_hosts)} unique hosts")
            if filter_internal and skipped_internal_count > 0:
                print(f"[Shodan] Filtered out {skipped_internal_count} internal IPs")

            # Build output
            output = {
                "query": query,
                "totalAvailable": total_available,
                "hostsReturned": len(all_hosts),
                "hosts": all_hosts,
                "tool": "shodan",
                "scan_type": "search",
            }
            if filter_internal and skipped_internal_count > 0:
                output["internalIPsFiltered"] = skipped_internal_count

            # Generate assets if requested
            assets = []
            if create_assets:
                for host in all_hosts:
                    assets.append({
                        "type": "IP_ADDRESS",
                        "value": host["ip"],
                        "metadata": {
                            "importSource": "shodan",
                            "shodanId": f"shodan-{host['ip']}",
                            "hostnames": host["hostnames"],
                            "org": host["org"],
                            "isp": host["isp"],
                            "asn": host["asn"],
                            "os": host["os"],
                            "geolocation": host["geolocation"],
                            "discoveredVia": f"shodan:search query={query}",
                        }
                    })

                    # Create FQDN assets for hostnames
                    for hostname in host.get("hostnames", []):
                        assets.append({
                            "type": "FQDN",
                            "value": hostname,
                            "metadata": {
                                "importSource": "shodan",
                                "resolvedIp": host["ip"],
                                "discoveredVia": f"shodan:search query={query}",
                            }
                        })

            return {
                "success": True,
                "output": output,
                "assets": assets,
                "summary": {
                    "query": query,
                    "totalAvailable": total_available,
                    "hostsReturned": len(all_hosts),
                    "assetsGenerated": len(assets),
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
                "error": f"Error searching Shodan: {str(e)}"
            }


def get_tool():
    return ShodanSearchTool()

"""
Nmap Quick Scan Tool
Scans top 1000 most common ports for fast results
"""

import asyncio
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from plugin_interface import ToolPlugin


class NmapQuickScanTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "nmap:quick_scan"

    @property
    def description(self) -> str:
        return "Quick scan of top 1000 most common ports using Nmap"

    @property
    def schema(self):
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "IP address, hostname, URL, or host:port to scan"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple IP addresses, hostnames, URLs, or host:port targets to scan (alternative to target)"
                }
            },
            "oneOf": [
                {"required": ["target"]},
                {"required": ["targets"]}
            ]
        }

    @property
    def metadata(self):
        return {
            "category": "enumeration",
            "phase": 3,
            "domain": ["infra"],
            "input_type": ["ip", "hostname"],
            "output_type": ["ports", "services"],
            "chainable_after": ["system:dns_resolve", "subfinder:", "httpx:"],
            "chainable_before": ["nuclei:", "testssl:", "httpx:probe"],
        }

    async def execute(self, parameters: dict):
        """Execute quick Nmap port scan"""
        target = parameters.get("target")
        targets = parameters.get("targets")

        if not target and not targets:
            return {
                "success": False,
                "error": "Either 'target' or 'targets' parameter is required"
            }

        # Build target list
        if targets:
            if isinstance(targets, str):
                import json
                try:
                    targets = json.loads(targets)
                except (json.JSONDecodeError, ValueError):
                    targets = [targets]
            if not isinstance(targets, list):
                targets = [targets]
        else:
            targets = [target]

        all_open_ports = []

        try:
            for scan_target in targets:
                normalized_target, explicit_port = self._split_host_port(str(scan_target))

                # Nmap does not accept host:port or URL strings as scan
                # targets. UI-created infra workflows naturally use
                # frontend:3000/backend:3001 style targets, so preserve that
                # UX while dispatching a valid host plus optional -p.
                port_args = ["-p", str(explicit_port)] if explicit_port else ["--top-ports", "1000"]
                cmd = ["nmap", "-Pn", "-sV", *port_args, "-oX", "-", normalized_target]

                port_label = f"port {explicit_port}" if explicit_port else "top 1000 ports"
                print(f"[Nmap Quick] Scanning {port_label} on {normalized_target}")
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                # Add timeout: quick scan should complete in 5 minutes max per target
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=300  # 5 minutes
                    )
                except asyncio.TimeoutError:
                    # Kill the process if it times out
                    process.kill()
                    await process.wait()
                    print(f"[Nmap Quick] Scan timed out for {scan_target}")
                    continue

                xml_output = stdout.decode('utf-8', errors='replace')
                stderr_output = stderr.decode('utf-8', errors='replace') if stderr else ""
                if stderr_output:
                    print(f"[Nmap Quick] stderr: {stderr_output[:500]}")

                # Parse XML to extract open ports with service info
                try:
                    root = ET.fromstring(xml_output)
                    for host in root.findall('.//host'):
                        for port in host.findall('.//port'):
                            state = port.find('state')
                            if state is not None and state.get('state') == 'open':
                                port_id = port.get('portid')
                                protocol = port.get('protocol')

                                # Extract service information
                                service_elem = port.find('service')
                                port_data = {
                                    'port': int(port_id),
                                    'protocol': protocol,
                                    'state': 'open',
                                    'target': normalized_target,
                                    'originalTarget': scan_target
                                }

                                if service_elem is not None:
                                    service_info = {
                                        'name': service_elem.get('name'),
                                        'product': service_elem.get('product'),
                                        'version': service_elem.get('version'),
                                        'extrainfo': service_elem.get('extrainfo')
                                    }
                                    if service_info.get('name'):
                                        port_data['service'] = service_info

                                all_open_ports.append(port_data)
                except Exception as e:
                    print(f"[Nmap Quick] XML parsing error for {scan_target}: {e}")

            print(f"[Nmap Quick] Found {len(all_open_ports)} open ports across {len(targets)} targets")

            return {
                "success": True,
                "output": {
                    "openPorts": all_open_ports,
                    "totalPorts": len(all_open_ports),
                    "target": targets[0] if len(targets) == 1 else f"{len(targets)} targets",
                    "targets": targets,
                    "tool": "nmap",
                    "scan_type": "quick_scan"
                },
                "raw_output": ""
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "Nmap not installed"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error running Nmap quick scan: {str(e)}"
            }

    def _split_host_port(self, raw_target: str):
        """Return (host, port) for URL or host:port targets."""
        target = raw_target.strip()
        if not target:
            return raw_target, None

        try:
            parsed = urlparse(target if "://" in target else f"//{target}", scheme="http")
            host = parsed.hostname
            port = parsed.port
            if host:
                return host, port
        except ValueError:
            pass

        if ":" in target and target.count(":") == 1:
            host_part, port_part = target.rsplit(":", 1)
            if port_part.isdigit():
                return host_part, int(port_part)

        return target, None


def get_tool():
    return NmapQuickScanTool()

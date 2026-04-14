"""
httpx HTTP Probe Tool
Probes hosts/URLs for HTTP services, capturing status codes, titles, web servers,
content types, and technology fingerprints. This is a DISCOVERY/ENRICHMENT tool.
"""

import asyncio
import json
import os
import time
from plugin_interface import ToolPlugin
from typing import Dict, Any


class HttpxProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "httpx:probe"

    @property
    def description(self) -> str:
        return "Probes hosts/URLs for live HTTP services. Returns status codes, titles, web servers, technologies, and content info. Supports single or multi-target probing with redirect following."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Single URL or host to probe (e.g., example.com or http://example.com)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple URLs/hosts to probe (alternative to target)"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to probe from array (default: 100)",
                    "default": 100
                },
                "followRedirects": {
                    "type": "boolean",
                    "description": "Follow HTTP redirects (default: true)",
                    "default": True
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
            "category": "discovery",
            "phase": 2,
            "domain": ["web"],
            "input_type": ["ip", "hostname", "url"],
            "output_type": ["urls", "services"],
            "chainable_after": ["system:dns_resolve", "subfinder:", "nmap:"],
            "chainable_before": ["katana:", "nuclei:", "dirsearch:", "gowitness:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')

        # Resolve targets
        targets_list = []
        if 'targets' in parameters and parameters['targets']:
            targets_param = parameters['targets']
            if isinstance(targets_param, str):
                try:
                    targets_list = json.loads(targets_param)
                except json.JSONDecodeError:
                    targets_list = [targets_param]
            elif isinstance(targets_param, list):
                targets_list = targets_param
            else:
                targets_list = [str(targets_param)]
        elif 'target' in parameters and parameters['target']:
            targets_list = [parameters['target']]

        if not targets_list:
            return {
                'success': False,
                'error': 'Either target or targets parameter is required',
                'output': {
                    'results': [],
                    'total': 0,
                    'tool': 'httpx',
                    'scan_type': 'probe'
                },
                'raw_output': ''
            }

        # Apply maxTargets limit
        max_targets = parameters.get('maxTargets', 100)
        if len(targets_list) > max_targets:
            print(f"[httpx] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]

        follow_redirects = parameters.get('followRedirects', True)

        start_time = time.time()

        if agent:
            agent.report_progress(
                current_operation=f"Starting httpx probe on {len(targets_list)} target(s)",
                current_target=targets_list[0],
                items_processed=0,
                total_items=len(targets_list)
            )

        # Build command
        cmd = [
            'httpx',
            '-json',
            '-silent',
            '-status-code',
            '-title',
            '-web-server',
            '-content-type',
            '-content-length',
            '-tech-detect',
            '-no-color'
        ]

        if follow_redirects:
            cmd.append('-follow-redirects')

        # Handle single vs multiple targets
        target_file = None
        if len(targets_list) == 1:
            cmd.extend(['-u', targets_list[0]])
            print(f"[httpx] Probing single target: {targets_list[0]}")
        else:
            target_file = f"/tmp/httpx_targets_{int(time.time())}.txt"
            with open(target_file, 'w') as f:
                f.write('\n'.join(targets_list))
            cmd.extend(['-l', target_file])
            print(f"[httpx] Probing {len(targets_list)} targets from file")

        print(f"[httpx] Command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300  # 5 minutes
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                elapsed = time.time() - start_time
                print(f"[httpx] Timeout after {elapsed:.1f}s")
                if agent:
                    agent.append_output(f"[httpx] Timeout after {elapsed:.1f}s")
                # Clean up temp file
                if target_file and os.path.exists(target_file):
                    os.remove(target_file)
                return {
                    'success': False,
                    'error': f'httpx probe timed out after 5 minutes',
                    'output': {
                        'results': [],
                        'total': 0,
                        'tool': 'httpx',
                        'scan_type': 'probe'
                    },
                    'raw_output': ''
                }

            # Clean up temp file
            if target_file and os.path.exists(target_file):
                os.remove(target_file)

            # Decode and sanitize
            stdout_text = stdout.decode('utf-8', errors='replace').replace('\0', '') if stdout else ''
            stderr_text = stderr.decode('utf-8', errors='replace').replace('\0', '') if stderr else ''

            return_code = process.returncode
            elapsed = time.time() - start_time

            print(f"[httpx] Completed in {elapsed:.1f}s (return code: {return_code})")
            print(f"[httpx] Stdout size: {len(stdout_text)} bytes")

            if return_code != 0 and not stdout_text:
                print(f"[httpx] Failed: {stderr_text[:500]}")
                return {
                    'success': False,
                    'error': stderr_text or 'httpx probe failed',
                    'output': {
                        'results': [],
                        'total': 0,
                        'tool': 'httpx',
                        'scan_type': 'probe'
                    },
                    'raw_output': stderr_text
                }

            # Parse JSON output line by line
            results = []
            parse_errors = 0

            for line in stdout_text.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    line = line.replace('\0', '')
                    data = json.loads(line)

                    result = {
                        'url': data.get('url', ''),
                        'status_code': data.get('status_code'),
                        'title': data.get('title', ''),
                        'webserver': data.get('webserver', ''),
                        'technologies': data.get('tech', []),
                        'content_type': data.get('content_type', ''),
                        'content_length': data.get('content_length'),
                        'host': data.get('host', ''),
                        'port': data.get('port', ''),
                    }

                    # Include final_url if redirect was followed
                    if data.get('final_url') and data.get('final_url') != data.get('url'):
                        result['final_url'] = data.get('final_url')

                    # Include scheme if available
                    if data.get('scheme'):
                        result['scheme'] = data.get('scheme')

                    results.append(result)
                except json.JSONDecodeError:
                    parse_errors += 1

            print(f"[httpx] Parsed {len(results)} results ({parse_errors} parse errors)")

            if agent:
                agent.report_progress(
                    current_operation="httpx probe completed",
                    current_target=targets_list[0],
                    items_processed=len(results),
                    total_items=len(results)
                )
                agent.append_output(f"[httpx] Probed {len(targets_list)} target(s), {len(results)} responded")
                # Show summary of live hosts
                live_count = sum(1 for r in results if r.get('status_code') and 200 <= r['status_code'] < 400)
                agent.append_output(f"[httpx] Live (2xx/3xx): {live_count}, Total responses: {len(results)}")

            # Limit raw output size
            raw_output = stdout_text
            if len(raw_output) > 5 * 1024 * 1024:
                lines = raw_output.split('\n')
                raw_output = '\n'.join(lines[:1000]) + f"\n... (truncated, total {len(lines)} lines)"

            # Build urls array for easy workflow chaining (downstream tools expect 'urls' or 'targets')
            urls = [r['url'] for r in results if r.get('url')]

            return {
                'success': True,
                'output': {
                    'results': results,
                    'urls': urls,  # Flat URL array for workflow chaining (katana, nuclei, dalfox, etc.)
                    'targets': urls,  # Alias for tools that expect 'targets'
                    'total': len(results),
                    'tool': 'httpx',
                    'scan_type': 'probe'
                },
                'raw_output': raw_output
            }

        except FileNotFoundError:
            if target_file and os.path.exists(target_file):
                os.remove(target_file)
            return {
                'success': False,
                'error': 'httpx not installed. Install with: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
                'output': {
                    'results': [],
                    'total': 0,
                    'tool': 'httpx',
                    'scan_type': 'probe'
                },
                'raw_output': ''
            }
        except Exception as e:
            if target_file and os.path.exists(target_file):
                os.remove(target_file)
            print(f"[httpx] Exception: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'output': {
                    'results': [],
                    'total': 0,
                    'tool': 'httpx',
                    'scan_type': 'probe'
                },
                'raw_output': ''
            }


def get_tool():
    return HttpxProbeTool()

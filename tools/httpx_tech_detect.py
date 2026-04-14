"""
httpx Technology Detection Tool
Focused variant of httpx that emphasizes technology fingerprinting and
web stack identification. Returns detailed technology stack information
for target hosts/URLs.
"""

import asyncio
import json
import os
import time
from plugin_interface import ToolPlugin
from typing import Dict, Any


class HttpxTechDetectTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "httpx:tech_detect"

    @property
    def description(self) -> str:
        return "Technology detection - fingerprints web technology stacks, frameworks, CMS, CDN, WAF, and server software using httpx with enhanced detection"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Single URL or host to scan (e.g., 'example.com' or 'http://example.com')"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple URLs/hosts to scan (alternative to target)"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to scan (default: 100)",
                    "default": 100
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
            "category": "enrichment",
            "phase": 2,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["httpx:probe", "katana:"],
            "chainable_before": ["nuclei:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get("_agent")
        job_id = parameters.get("_job_id", "unknown")

        # Resolve targets
        targets_list = []
        if "targets" in parameters and parameters["targets"]:
            targets_param = parameters["targets"]
            if isinstance(targets_param, str):
                try:
                    targets_list = json.loads(targets_param)
                except json.JSONDecodeError:
                    targets_list = [targets_param]
            elif isinstance(targets_param, list):
                targets_list = targets_param
            else:
                targets_list = [str(targets_param)]
        elif "target" in parameters and parameters["target"]:
            targets_list = [parameters["target"]]

        if not targets_list:
            return {
                "success": False,
                "error": "Either 'target' or 'targets' parameter is required",
                "output": {
                    "results": [],
                    "total": 0,
                    "tool": "httpx",
                    "scan_type": "tech_detect"
                },
                "raw_output": ""
            }

        # Apply maxTargets limit
        max_targets = parameters.get("maxTargets", 100)
        if len(targets_list) > max_targets:
            print(f"[httpx:tech] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]

        total_targets = len(targets_list)
        scan_label = targets_list[0] if total_targets == 1 else f"{total_targets} targets"
        print(f"[httpx:tech] Technology detection on {scan_label}")

        start_time = time.time()

        if agent:
            agent.report_progress(
                current_operation="Starting technology detection",
                current_target=scan_label,
                items_processed=0,
                total_items=total_targets
            )
            agent.append_output(f"[httpx:tech] Scanning {scan_label} for technology stack...")

        # Build command with tech-focused flags
        cmd = [
            "httpx",
            "-json",
            "-silent",
            "-tech-detect",
            "-status-code",
            "-title",
            "-web-server",
            "-content-type",
            "-content-length",
            "-no-color",
            "-follow-redirects"
        ]

        # Handle single vs multiple targets
        target_file = None
        if total_targets == 1:
            cmd.extend(["-u", targets_list[0]])
        else:
            target_file = f"/tmp/httpx_tech_{job_id}_{int(time.time())}.txt"
            with open(target_file, "w") as f:
                f.write("\n".join(targets_list))
            cmd.extend(["-l", target_file])

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
                print("[httpx:tech] Timeout after 5 minutes")
                if agent:
                    agent.append_output("[httpx:tech] Scan timed out after 5 minutes")
                return {
                    "success": False,
                    "error": "httpx tech detection timed out after 5 minutes",
                    "output": {
                        "results": [],
                        "total": 0,
                        "tool": "httpx",
                        "scan_type": "tech_detect"
                    },
                    "raw_output": ""
                }

            stdout_text = stdout.decode("utf-8", errors="replace").replace("\0", "") if stdout else ""
            stderr_text = stderr.decode("utf-8", errors="replace").replace("\0", "") if stderr else ""

            elapsed = time.time() - start_time
            print(f"[httpx:tech] Completed in {elapsed:.1f}s (rc: {process.returncode})")

            if process.returncode != 0:
                if not stdout_text:
                    return {
                        "success": False,
                        "error": stderr_text or f"httpx tech detection failed with exit code {process.returncode}",
                        "output": {
                            "results": [],
                            "total": 0,
                            "tool": "httpx",
                            "scan_type": "tech_detect"
                        },
                        "raw_output": stderr_text
                    }
                else:
                    print(f"[httpx:tech] Warning: httpx exited with code {process.returncode} but produced output, parsing results")

            # Parse JSON output
            results = []
            tech_summary = {}  # Aggregate technology counts

            for line in stdout_text.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    data = json.loads(line.replace("\0", ""))
                    techs = data.get("tech", [])

                    result = {
                        "url": data.get("url", ""),
                        "host": data.get("host", ""),
                        "port": data.get("port", ""),
                        "status_code": data.get("status_code"),
                        "title": data.get("title", ""),
                        "webserver": data.get("webserver", ""),
                        "technologies": techs,
                        "content_type": data.get("content_type", ""),
                    }

                    if data.get("scheme"):
                        result["scheme"] = data["scheme"]

                    results.append(result)

                    # Aggregate tech counts
                    for tech in techs:
                        tech_summary[tech] = tech_summary.get(tech, 0) + 1

                except json.JSONDecodeError:
                    pass

            print(f"[httpx:tech] Detected technologies on {len(results)} hosts")

            if agent:
                agent.report_progress(
                    current_operation="Technology detection complete",
                    current_target=scan_label,
                    items_processed=total_targets,
                    total_items=total_targets
                )
                agent.append_output(
                    f"[httpx:tech] Scanned {total_targets} targets, {len(results)} responded"
                )
                if tech_summary:
                    top_techs = sorted(tech_summary.items(), key=lambda x: x[1], reverse=True)[:10]
                    tech_str = ", ".join(f"{t}({c})" for t, c in top_techs)
                    agent.append_output(f"[httpx:tech] Top technologies: {tech_str}")

            raw_output = stdout_text
            if len(raw_output) > 5 * 1024 * 1024:
                lines = raw_output.split("\n")
                raw_output = "\n".join(lines[:1000]) + f"\n... (truncated, total {len(lines)} lines)"

            # Build urls array for workflow chaining
            urls = [r['url'] for r in results if r.get('url')]

            return {
                "success": True,
                "output": {
                    "results": results,
                    "urls": urls,  # Flat URL array for workflow chaining
                    "targets": urls,  # Alias for tools expecting 'targets'
                    "total": len(results),
                    "tech_summary": tech_summary,
                    "tool": "httpx",
                    "scan_type": "tech_detect"
                },
                "raw_output": raw_output
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "httpx is not installed or not in PATH",
                "output": {
                    "results": [],
                    "total": 0,
                    "tool": "httpx",
                    "scan_type": "tech_detect"
                },
                "raw_output": ""
            }
        except Exception as e:
            print(f"[httpx:tech] Error: {e}")
            return {
                "success": False,
                "error": str(e),
                "output": {
                    "results": [],
                    "total": 0,
                    "tool": "httpx",
                    "scan_type": "tech_detect"
                },
                "raw_output": ""
            }
        finally:
            if target_file and os.path.exists(target_file):
                try:
                    os.remove(target_file)
                except Exception:
                    pass


def get_tool():
    return HttpxTechDetectTool()

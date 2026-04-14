"""
GoWitness Screenshot Tool
Takes screenshots of web applications
"""

import asyncio
import json
import os
import time
from plugin_interface import ToolPlugin
from typing import Dict, Any, Optional
from tools.screenshot_utils import find_chrome_path, compute_sha256


class GoWitnessScreenshotTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "gowitness:screenshot"

    @property
    def description(self) -> str:
        return "Takes screenshots of web applications using GoWitness"

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "URL to screenshot (e.g., http://example.com/path)"
                },
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Multiple URLs to screenshot (alternative to target, for workflow chaining)"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets to screenshot from array (default: 20)",
                    "default": 20
                },
                "brandMonitorId": {
                    "type": "string",
                    "description": "Optional brand monitor ID for organized output paths"
                },
                "typosquatDomainId": {
                    "type": "string",
                    "description": "Optional typosquat domain ID for organized output paths"
                },
                "outputDir": {
                    "type": "string",
                    "description": "Custom output directory for screenshots (default: /tmp/agent_outputs/screenshots)"
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
            "category": "screenshot",
            "phase": 3,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["screenshots"],
            "chainable_after": ["httpx:probe", "katana:", "dirsearch:"],
            "chainable_before": [],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')

        # Resolve targets list
        targets_list = self._resolve_targets(parameters)
        if not targets_list:
            return {
                'success': False,
                'error': 'Either target or targets parameter is required',
                'output': {
                    'screenshots': [],
                    'targets': [],
                    'total': 0,
                    'tool': 'gowitness',
                    'scan_type': 'screenshot'
                },
                'raw_output': ''
            }

        # Apply maxTargets limit
        max_targets = parameters.get('maxTargets', 20)
        if len(targets_list) > max_targets:
            print(f"[GoWitness] Limiting {len(targets_list)} targets to {max_targets}")
            targets_list = targets_list[:max_targets]

        # Determine output directory
        brand_monitor_id = parameters.get('brandMonitorId')
        typosquat_domain_id = parameters.get('typosquatDomainId')
        output_dir = parameters.get('outputDir', '/tmp/agent_outputs/screenshots')

        screenshots_dir = output_dir
        os.makedirs(screenshots_dir, exist_ok=True)

        if agent:
            agent.report_progress(
                current_operation=f"Starting screenshots for {len(targets_list)} target(s)",
                current_target=targets_list[0],
                items_processed=0,
                total_items=len(targets_list)
            )

        screenshots = []
        all_raw = []

        for idx, target in enumerate(targets_list):
            try:
                # Determine screenshot output path
                if brand_monitor_id:
                    subfolder = typosquat_domain_id or 'reference'
                    target_dir = os.path.join(
                        screenshots_dir, 'brand-monitoring',
                        brand_monitor_id, subfolder
                    )
                    os.makedirs(target_dir, exist_ok=True)
                else:
                    target_dir = screenshots_dir

                chrome_path = find_chrome_path()
                gowitness_cmd = [
                    'gowitness', 'scan', 'single', '--url', target,
                    '--screenshot-path', target_dir,
                ]
                if chrome_path:
                    gowitness_cmd.extend(['--chrome-path', chrome_path])

                process = await asyncio.create_subprocess_exec(
                    *gowitness_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(),
                        timeout=60  # 1 minute max per target
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    if agent:
                        agent.append_output(f"[GoWitness] Timeout on {target}")
                    screenshots.append({'target': target, 'success': False, 'error': 'timeout'})
                    continue

                stdout_text = stdout.decode('utf-8', errors='replace') if stdout else ''
                stderr_text = stderr.decode('utf-8', errors='replace') if stderr else ''
                all_raw.append(f"# {target}\n{stdout_text}\n{stderr_text}")

                # Wait briefly for file to be written, then find the screenshot
                await asyncio.sleep(1)

                # Find the most recent screenshot file
                screenshot_file = self._find_recent_screenshot(target_dir)

                if screenshot_file:
                    screenshot_path = os.path.join(target_dir, screenshot_file)
                    file_hash = compute_sha256(screenshot_path)
                    file_size = os.path.getsize(screenshot_path)

                    # Build relative path if using brand monitoring structure
                    if brand_monitor_id:
                        subfolder = typosquat_domain_id or 'reference'
                        relative_path = os.path.join(
                            'brand-monitoring', brand_monitor_id,
                            subfolder, screenshot_file
                        )
                    else:
                        relative_path = screenshot_file

                    screenshots.append({
                        'target': target,
                        'screenshot_path': screenshot_path,
                        'screenshot_filename': screenshot_file,
                        'filePath': relative_path,
                        'fileHash': f'sha256:{file_hash}',
                        'fileSize': file_size,
                        'success': True
                    })
                    if agent:
                        agent.append_output(f"[GoWitness] {target}: screenshot saved ({file_size} bytes)")
                else:
                    screenshots.append({
                        'target': target,
                        'success': False,
                        'error': 'Screenshot file not found'
                    })
                    if agent:
                        agent.append_output(f"[GoWitness] {target}: screenshot not found")

                if agent:
                    agent.report_progress(
                        current_operation="Taking screenshots",
                        current_target=target,
                        items_processed=idx + 1,
                        total_items=len(targets_list)
                    )

            except FileNotFoundError:
                return {
                    'success': False,
                    'error': 'GoWitness not installed. Install from: https://github.com/sensepost/gowitness',
                    'output': {
                        'screenshots': [],
                        'targets': [],
                        'total': 0,
                        'tool': 'gowitness',
                        'scan_type': 'screenshot'
                    },
                    'raw_output': ''
                }
            except Exception as e:
                screenshots.append({'target': target, 'success': False, 'error': str(e)})

        if agent:
            agent.report_progress(
                current_operation="Screenshots completed",
                current_target=targets_list[0],
                items_processed=len(targets_list),
                total_items=len(targets_list)
            )
            successful = sum(1 for s in screenshots if s.get('success'))
            agent.append_output(f"[GoWitness] {successful}/{len(targets_list)} screenshots captured")

        raw_output = '\n'.join(all_raw)

        return {
            'success': True,
            'output': {
                'screenshots': screenshots,
                'targets': targets_list,
                'total': len(screenshots),
                'successful': sum(1 for s in screenshots if s.get('success')),
                'tool': 'gowitness',
                'scan_type': 'screenshot'
            },
            'raw_output': raw_output
        }

    def _resolve_targets(self, parameters: Dict[str, Any]) -> list:
        """Resolve target/targets parameter into a list."""
        if 'targets' in parameters and parameters['targets']:
            targets_param = parameters['targets']
            if isinstance(targets_param, str):
                try:
                    return json.loads(targets_param)
                except json.JSONDecodeError:
                    return [targets_param]
            elif isinstance(targets_param, list):
                return targets_param
            else:
                return [str(targets_param)]
        elif 'target' in parameters and parameters['target']:
            return [parameters['target']]
        return []

    def _find_recent_screenshot(self, directory: str) -> str:
        """Find the most recently created screenshot file."""
        try:
            img_files = [f for f in os.listdir(directory) if f.endswith(('.png', '.jpeg', '.jpg'))]
            if not img_files:
                return None
            # Sort by modification time, newest first
            img_files.sort(key=lambda f: os.path.getmtime(os.path.join(directory, f)), reverse=True)
            # Return the newest file if it was created in the last 30 seconds
            newest = img_files[0]
            if os.path.getmtime(os.path.join(directory, newest)) > time.time() - 30:
                return newest
        except Exception:
            pass
        return None

def get_tool():
    return GoWitnessScreenshotTool()

"""
Brand Monitor Screenshot Tool
Specialized composite tool for brand monitoring screenshot cycles.
Wraps gowitness functionality for brand monitoring with perceptual hashing
and change detection support.
"""

import asyncio
import hashlib
import json
import os
import time
from plugin_interface import ToolPlugin
from typing import Dict, Any, List, Optional
from tools.screenshot_utils import find_chrome_path, compute_sha256


UA_PROFILES = {
    'desktop': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'mobile': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'bot': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
}


class BrandMonitorScreenshotTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "brand_monitor:screenshot"

    @property
    def description(self) -> str:
        return (
            "Captures screenshots of typosquatting domains for brand monitoring. "
            "Computes SHA-256 and perceptual hashes for change detection and "
            "visual similarity comparison."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "URLs to screenshot"
                },
                "brandMonitorId": {
                    "type": "string",
                    "description": "Brand monitor ID to associate screenshots with"
                },
                "typosquatDomainMap": {
                    "type": "object",
                    "description": "Mapping of URL -> typosquatDomainId"
                },
                "brandKeywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Brand keywords to detect in page content"
                },
                "outputDir": {
                    "type": "string",
                    "description": "Output directory for screenshots (default: /app-storage/screenshots)",
                    "default": "/app-storage/screenshots"
                },
                "maxTargets": {
                    "type": "integer",
                    "description": "Maximum number of targets (default: 50)",
                    "default": 50
                },
                "enableMultiUA": {
                    "type": "boolean",
                    "description": "Capture screenshots with desktop, mobile, and bot user agents to detect cloaking (default: false)",
                    "default": False
                }
            },
            "required": ["targets"]
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "screenshot",
            "phase": 3,
            "domain": ["web", "osint"],
            "input_type": ["url"],
            "output_type": ["screenshots"],
            "chainable_after": ["typosquat:detect", "httpx:probe"],
            "chainable_before": [],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')

        targets = parameters.get('targets', [])
        if isinstance(targets, str):
            try:
                targets = json.loads(targets)
            except json.JSONDecodeError:
                targets = [targets]

        brand_monitor_id = parameters.get('brandMonitorId')
        typosquat_domain_map = parameters.get('typosquatDomainMap', {})
        if isinstance(typosquat_domain_map, str):
            try:
                typosquat_domain_map = json.loads(typosquat_domain_map)
            except json.JSONDecodeError:
                typosquat_domain_map = {}

        output_dir = parameters.get('outputDir', '/app-storage/screenshots')
        max_targets = parameters.get('maxTargets', 50)
        enable_multi_ua = parameters.get('enableMultiUA', False)

        if not targets:
            return {
                'success': False,
                'error': 'targets parameter is required',
                'output': {
                    'screenshots': [],
                    'brandMonitorId': brand_monitor_id,
                    'total': 0,
                    'successful': 0,
                    'tool': 'brand_monitor',
                    'scan_type': 'screenshot',
                }
            }

        if not brand_monitor_id:
            return {
                'success': False,
                'error': 'brandMonitorId parameter is required',
                'output': {
                    'screenshots': [],
                    'brandMonitorId': None,
                    'total': 0,
                    'successful': 0,
                    'tool': 'brand_monitor',
                    'scan_type': 'screenshot',
                }
            }

        # Apply limit
        if len(targets) > max_targets:
            print(f"[BrandMonitor:Screenshot] Limiting {len(targets)} targets to {max_targets}")
            targets = targets[:max_targets]

        if agent:
            agent.report_progress(
                current_operation=f"Starting brand monitor screenshots for {len(targets)} target(s)",
                current_target=targets[0],
                items_processed=0,
                total_items=len(targets),
            )

        screenshots: List[Dict[str, Any]] = []
        total_ops = len(targets) * (len(UA_PROFILES) if enable_multi_ua else 1)

        for idx, url in enumerate(targets):
            typosquat_domain_id = typosquat_domain_map.get(url)

            if enable_multi_ua:
                ua_results: List[Dict[str, Any]] = []
                for ua_idx, (ua_key, ua_string) in enumerate(UA_PROFILES.items()):
                    result = await self._capture_screenshot(
                        url=url,
                        brand_monitor_id=brand_monitor_id,
                        typosquat_domain_id=typosquat_domain_id,
                        output_dir=output_dir,
                        user_agent_key=ua_key,
                        user_agent_string=ua_string,
                    )
                    ua_results.append(result)

                    if agent:
                        status = "OK" if result['success'] else f"FAIL: {result.get('error', 'unknown')}"
                        agent.append_output(f"[BrandMonitor:Screenshot] {url} [{ua_key}]: {status}")
                        op_num = idx * len(UA_PROFILES) + ua_idx + 1
                        agent.report_progress(
                            current_operation=f"Capturing multi-UA screenshots ({ua_key})",
                            current_target=url,
                            items_processed=op_num,
                            total_items=total_ops,
                        )

                # Detect cloaking across UAs
                cloaking = self._detect_cloaking(ua_results)
                for result in ua_results:
                    result['cloakingDetected'] = cloaking['detected']
                    result['cloakingScore'] = cloaking['score']
                screenshots.extend(ua_results)
            else:
                result = await self._capture_screenshot(
                    url=url,
                    brand_monitor_id=brand_monitor_id,
                    typosquat_domain_id=typosquat_domain_id,
                    output_dir=output_dir,
                )
                result['userAgent'] = 'desktop'
                screenshots.append(result)

                if agent:
                    status = "OK" if result['success'] else f"FAIL: {result.get('error', 'unknown')}"
                    agent.append_output(f"[BrandMonitor:Screenshot] {url}: {status}")
                    agent.report_progress(
                        current_operation="Capturing brand monitor screenshots",
                        current_target=url,
                        items_processed=idx + 1,
                        total_items=total_ops,
                    )

        successful = sum(1 for s in screenshots if s['success'])

        if agent:
            agent.report_progress(
                current_operation=f"Brand monitor screenshots completed: {successful}/{len(targets)}",
                current_target=targets[0],
                items_processed=len(targets),
                total_items=len(targets),
            )
            agent.append_output(
                f"[BrandMonitor:Screenshot] {successful}/{len(targets)} screenshots captured"
            )

        return {
            'success': True,
            'output': {
                'screenshots': [self._sanitize(s) for s in screenshots],
                'brandMonitorId': brand_monitor_id,
                'typosquatDomainMap': typosquat_domain_map,
                'total': len(screenshots),
                'successful': successful,
                'tool': 'brand_monitor',
                'scan_type': 'screenshot',
            }
        }

    async def _capture_screenshot(
        self,
        url: str,
        brand_monitor_id: str,
        typosquat_domain_id: Optional[str],
        output_dir: str,
        user_agent_key: Optional[str] = None,
        user_agent_string: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Capture a single screenshot with hashing."""
        subfolder = typosquat_domain_id or 'reference'
        target_dir = os.path.join(
            output_dir, 'brand-monitoring', brand_monitor_id, subfolder
        )
        os.makedirs(target_dir, exist_ok=True)

        try:
            chrome_path = find_chrome_path()
            gowitness_cmd = [
                'gowitness', 'scan', 'single', '--url', url,
                '--screenshot-path', target_dir,
                '--delay', '5', '--timeout', '30',
            ]
            if user_agent_string:
                gowitness_cmd.extend(['--chrome-user-agent', user_agent_string])
            if chrome_path:
                gowitness_cmd.extend(['--chrome-path', chrome_path])

            process = await asyncio.create_subprocess_exec(
                *gowitness_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=60
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return {
                    'target': url,
                    'success': False,
                    'error': 'timeout',
                    'filePath': None,
                    'fileHash': None,
                    'perceptualHash': None,
                    'fileSize': 0,
                    'httpStatusCode': None,
                    'pageTitle': None,
                    'hasContent': False,
                }

            # Wait briefly for file to appear
            await asyncio.sleep(1)

            # Find the most recent screenshot
            screenshot_file = self._find_recent_screenshot(target_dir)
            if not screenshot_file:
                return {
                    'target': url,
                    'success': False,
                    'error': 'Screenshot file not found after capture',
                    'filePath': None,
                    'fileHash': None,
                    'perceptualHash': None,
                    'fileSize': 0,
                    'httpStatusCode': None,
                    'pageTitle': None,
                    'hasContent': False,
                }

            # Rename to a deterministic name with timestamp
            timestamp = int(time.time())
            url_hash = hashlib.sha256(url.encode()).hexdigest()[:12]
            ext = os.path.splitext(screenshot_file)[1] or '.jpeg'
            ua_suffix = f"_{user_agent_key}" if user_agent_key else ""
            new_filename = f"{timestamp}_{url_hash}{ua_suffix}{ext}"
            old_path = os.path.join(target_dir, screenshot_file)
            new_path = os.path.join(target_dir, new_filename)
            os.rename(old_path, new_path)

            file_hash = compute_sha256(new_path)
            file_size = os.path.getsize(new_path)
            perceptual_hash = self._compute_perceptual_hash(new_path)

            has_content = self._has_meaningful_content(new_path)

            # Protocol fallback: if blank screenshot and URL is https, retry with http
            if not has_content and url.startswith('https://'):
                import re as _re
                domain_match = _re.match(r'https://([^/]+)', url)
                if domain_match:
                    http_url = f'http://{domain_match.group(1)}'
                    print(f"[BrandMonitor:Screenshot] Blank screenshot for {url}, retrying with {http_url}")
                    retry_cmd = [
                        'gowitness', 'scan', 'single', '--url', http_url,
                        '--screenshot-path', target_dir,
                        '--delay', '5', '--timeout', '30',
                    ]
                    if user_agent_string:
                        retry_cmd.extend(['--chrome-user-agent', user_agent_string])
                    if chrome_path:
                        retry_cmd.extend(['--chrome-path', chrome_path])
                    retry_proc = await asyncio.create_subprocess_exec(
                        *retry_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    try:
                        stdout, stderr = await asyncio.wait_for(
                            retry_proc.communicate(), timeout=60
                        )
                    except asyncio.TimeoutError:
                        retry_proc.kill()
                        await retry_proc.wait()
                    else:
                        await asyncio.sleep(3)
                        retry_file = self._find_recent_screenshot(target_dir)
                        if retry_file and retry_file != new_filename:
                            retry_path = os.path.join(target_dir, retry_file)
                            if self._has_meaningful_content(retry_path):
                                # Replace with the http screenshot
                                print(f"[BrandMonitor:Screenshot] HTTP fallback succeeded for {url}")
                                os.remove(new_path)
                                timestamp = int(time.time())
                                new_filename = f"{timestamp}_{url_hash}{ua_suffix}{ext}"
                                new_path = os.path.join(target_dir, new_filename)
                                os.rename(retry_path, new_path)
                                file_hash = compute_sha256(new_path)
                                file_size = os.path.getsize(new_path)
                                perceptual_hash = self._compute_perceptual_hash(new_path)
                                has_content = True
                            else:
                                print(f"[BrandMonitor:Screenshot] HTTP fallback also produced blank screenshot for {url}")
                        else:
                            print(f"[BrandMonitor:Screenshot] HTTP fallback produced no new file for {url}")

            relative_path = os.path.join(
                'brand-monitoring', brand_monitor_id, subfolder, new_filename
            )

            # Parse HTTP status from gowitness output
            stdout_text = stdout.decode('utf-8', errors='replace') if stdout else ''
            http_status = self._extract_http_status(stdout_text)
            page_title = self._extract_page_title(stdout_text)

            return {
                'target': url,
                'filePath': relative_path,
                'fileHash': f'sha256:{file_hash}',
                'perceptualHash': f'phash:{perceptual_hash}' if perceptual_hash else None,
                'fileSize': file_size,
                'httpStatusCode': http_status,
                'pageTitle': page_title,
                'hasContent': has_content,
                'userAgent': user_agent_key or 'desktop',
                'success': True,
                'error': None,
            }

        except FileNotFoundError:
            return {
                'target': url,
                'success': False,
                'error': 'GoWitness not installed',
                'filePath': None,
                'fileHash': None,
                'perceptualHash': None,
                'fileSize': 0,
                'httpStatusCode': None,
                'pageTitle': None,
                'hasContent': False,
            }
        except Exception as e:
            return {
                'target': url,
                'success': False,
                'error': str(e),
                'filePath': None,
                'fileHash': None,
                'perceptualHash': None,
                'fileSize': 0,
                'httpStatusCode': None,
                'pageTitle': None,
                'hasContent': False,
            }

    @staticmethod
    def _sanitize(obj):
        """Recursively convert numpy types to native Python types for JSON serialization."""
        if isinstance(obj, dict):
            return {k: BrandMonitorScreenshotTool._sanitize(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [BrandMonitorScreenshotTool._sanitize(v) for v in obj]
        # Handle numpy scalar types
        try:
            import numpy as np
            if isinstance(obj, (np.bool_, np.integer)):
                return int(obj) if isinstance(obj, np.integer) else bool(obj)
            if isinstance(obj, np.floating):
                return float(obj)
        except ImportError:
            pass
        return obj

    def _find_recent_screenshot(self, directory: str) -> Optional[str]:
        """Find the most recently created screenshot file."""
        try:
            img_files = [f for f in os.listdir(directory) if f.endswith(('.png', '.jpeg', '.jpg', '.webp'))]
            if not img_files:
                print(f"[BrandMonitor:Screenshot] No image files found in {directory}")
                return None
            img_files.sort(
                key=lambda f: os.path.getmtime(os.path.join(directory, f)),
                reverse=True,
            )
            newest = img_files[0]
            file_age = time.time() - os.path.getmtime(os.path.join(directory, newest))
            if file_age < 120:
                return newest
            print(f"[BrandMonitor:Screenshot] Newest file {newest} is {file_age:.0f}s old (threshold: 120s)")
        except Exception as e:
            print(f"[BrandMonitor:Screenshot] Error finding screenshot in {directory}: {e}")
        return None

    def _compute_perceptual_hash(self, file_path: str) -> Optional[str]:
        """Compute perceptual hash using imagehash library."""
        try:
            import imagehash
            from PIL import Image
            img = Image.open(file_path)
            phash = imagehash.phash(img)
            return str(phash)
        except Exception as e:
            print(f"[BrandMonitor:Screenshot] Perceptual hash failed: {e}")
            return None

    def _has_meaningful_content(self, file_path: str) -> bool:
        """Check if screenshot has meaningful content using image entropy."""
        try:
            from PIL import Image
            import numpy as np
            img = Image.open(file_path).convert('L')  # grayscale
            pixels = np.array(img)
            std_dev = pixels.std()
            # Blank/white/solid pages have very low std deviation
            # Use low threshold (5) to accept parking pages and simple sites
            return bool(std_dev > 5)
        except Exception:
            # Fallback to file size check
            return os.path.getsize(file_path) > 5120

    def _extract_http_status(self, output: str) -> Optional[int]:
        """Try to extract HTTP status code from gowitness output."""
        import re
        matches = re.findall(r'\b(\d{3})\b', output)
        # Use the last match (final status after redirects)
        for m in reversed(matches):
            code = int(m)
            if 100 <= code <= 599:
                return code
        return None

    def _extract_page_title(self, output: str) -> Optional[str]:
        """Try to extract page title from gowitness output."""
        import re
        match = re.search(r'title[=:]\s*"?([^"\n]+)"?', output, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:255]
        return None

    def _detect_cloaking(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compare screenshots across UA profiles to detect cloaking.

        Uses perceptual hash Hamming distance when available, falls back to
        SHA file hash comparison. Returns detected=True when any pair exceeds
        the normalized distance threshold of 0.15.
        """
        successful = [r for r in results if r.get('success') and r.get('filePath')]
        if len(successful) < 2:
            return {'detected': False, 'score': 0.0}

        max_distance = 0.0

        # Try perceptual hash comparison first
        phashes = []
        for r in successful:
            raw = r.get('perceptualHash')
            if raw and raw.startswith('phash:'):
                phashes.append((r, raw[len('phash:'):]))

        if len(phashes) >= 2:
            try:
                import imagehash
                parsed = [(r, imagehash.hex_to_hash(h)) for r, h in phashes]
                hash_bit_length = len(parsed[0][1].hash.flatten())
                for i in range(len(parsed)):
                    for j in range(i + 1, len(parsed)):
                        hamming = parsed[i][1] - parsed[j][1]
                        normalized = hamming / hash_bit_length if hash_bit_length > 0 else 0.0
                        if normalized > max_distance:
                            max_distance = normalized
            except Exception as e:
                print(f"[BrandMonitor:Screenshot] pHash cloaking comparison failed, falling back to SHA: {e}")
                phashes = []  # fall through to SHA comparison

        # Fallback: compare SHA file hashes
        if len(phashes) < 2:
            file_hashes = [r.get('fileHash') for r in successful if r.get('fileHash')]
            unique_hashes = set(file_hashes)
            if len(unique_hashes) > 1:
                # Different file hashes = cloaking likely
                max_distance = 1.0
            else:
                max_distance = 0.0

        detected = max_distance > 0.15
        return {'detected': detected, 'score': round(max_distance, 4)}


def get_tool():
    return BrandMonitorScreenshotTool()

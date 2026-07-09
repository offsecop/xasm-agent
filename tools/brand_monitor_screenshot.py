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
import re
import socket
import time
from urllib.parse import urlparse
from plugin_interface import ToolPlugin
from typing import Dict, Any, List, Optional
from tools.screenshot_utils import find_chrome_path, compute_sha256
from lib.process_reaper import terminate_group, register_group

# #574 — fail-fast capture tuning. Tightened from gowitness's generous
# --timeout 30 / --delay 5 so a live-but-slow host is bounded to ~10s and a
# 9-target chunk stays well inside the 300s per-job watchdog. Env-tunable so
# cloud can adjust without a code change.
GOWITNESS_TIMEOUT = os.environ.get('DRP_GOWITNESS_TIMEOUT', '10')
GOWITNESS_DELAY = os.environ.get('DRP_GOWITNESS_DELAY', '1')
# Per-precheck network budget: DNS resolve + TCP connect each get this long, so a
# dead host short-circuits (zero Chromium) in a few seconds at most.
PRECHECK_TIMEOUT = float(os.environ.get('DRP_SCREENSHOT_PRECHECK_TIMEOUT', '2.0'))


UA_PROFILES = {
    'desktop': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'mobile': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
    'bot': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
}

CLOAKING_DISTANCE_THRESHOLD = 0.55

# #880 — parking / for-sale landing-page fingerprint. A GoDaddy/Sedo/etc. for-sale
# lander legitimately serves DIFFERENT content to bot vs human captures (per-request
# ad/upsell rotation), so bot-vs-human pHashes diverge past the cloaking threshold —
# but that is NOT consciousness-of-guilt cloaking. When a capture's final host (post
# redirect) is a known parking service OR its title matches the for-sale pattern,
# the cloaking signal is suppressed and the domain is fingerprinted `parked` so the
# scorer's lifecycle_dampen arms for the sibling alerts.
PARKING_HOSTS = frozenset({
    'forsale.godaddy.com',
    'sedoparking.com',
    'afternic.com',
    'dan.com',
    'parkingcrew.net',
    'bodis.com',
})
PARKING_TITLE_RE = re.compile(
    r'(domain (is )?for sale|parked free|this domain may be for sale|buy this domain)',
    re.IGNORECASE,
)


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

        # Orphaned Chromium from a previous timed-out capture is now collected by
        # the agent's periodic reaper (#571), not a per-job-start sweep here.

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
        # Cloud GCS write path: backend dispatches storageDriver (default "local")
        # and screenshotKeyPrefix (literal "screenshots"). When the driver is
        # "local" the GCS branch in _capture_screenshot is skipped entirely and
        # behaviour is byte-identical to today (gowitness writes the shared volume).
        storage_driver = (parameters.get('storageDriver') or 'local')
        screenshot_key_prefix = parameters.get('screenshotKeyPrefix', 'screenshots')

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
                        storage_driver=storage_driver,
                        screenshot_key_prefix=screenshot_key_prefix,
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
                    # #880 — parking/for-sale fingerprint; ingestion stamps
                    # metadata.parkedFingerprint so computeLifecycleStage → 'parked'.
                    result['parkedFingerprint'] = cloaking.get('parked', False)
                screenshots.extend(ua_results)
            else:
                result = await self._capture_screenshot(
                    url=url,
                    brand_monitor_id=brand_monitor_id,
                    typosquat_domain_id=typosquat_domain_id,
                    output_dir=output_dir,
                    storage_driver=storage_driver,
                    screenshot_key_prefix=screenshot_key_prefix,
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

    @staticmethod
    def _alternate_protocol_url(url: str) -> Optional[str]:
        """Return the same URL on the opposite scheme (http<->https), or None.

        The backend picks a single scheme from a possibly-stale ``hasSslCert``,
        so the opposite scheme is the natural fallback when the primary scheme
        produces a failed or blank capture. Path/query are preserved.
        """
        if url.startswith('https://'):
            return 'http://' + url[len('https://'):]
        if url.startswith('http://'):
            return 'https://' + url[len('http://'):]
        return None

    @staticmethod
    async def _host_resolves(host: Optional[str]) -> str:
        """#574/#884 — TRI-STATE DNS liveness pre-check (shared by both schemes).

        Returns one of:
          'resolves'  — getaddrinfo succeeded (host has an address).
          'nxdomain'  — an AUTHORITATIVE "no such name" (``EAI_NONAME`` /
                        ``EAI_NODATA``): the host is dead on EVERY scheme, so the
                        caller short-circuits the browser launch (the #574
                        fast-fail, preserved).
          'ambiguous' — a TRANSIENT resolver failure (``EAI_AGAIN`` "temporary
                        failure", a timeout, or any other ``OSError``): the
                        RESOLVER, not the host, is the problem. #884 — collapsing
                        this into "dead" converted 29 live, registered lookalikes
                        into confident "host does not resolve (DNS)" verdicts
                        during a resolver outage, dropped them from evidence, and
                        drove the capture breaker toward permanent give-up. The
                        caller must NOT stamp the dead verdict — it proceeds to the
                        browser attempt instead.

        Uses the stdlib resolver off the event loop; no new dependency.
        """
        if not host:
            return 'nxdomain'
        # Authoritative-negative errnos. EAI_NODATA is absent on some platforms,
        # so probe defensively (keeps the unit test portable across OSes).
        nxdomain_errnos = set()
        for name in ('EAI_NONAME', 'EAI_NODATA'):
            val = getattr(socket, name, None)
            if val is not None:
                nxdomain_errnos.add(val)
        try:
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP),
                timeout=PRECHECK_TIMEOUT,
            )
            return 'resolves'
        except socket.gaierror as e:
            # Only an authoritative "no such name" is a definitive dead host; a
            # transient EAI_AGAIN (and any other gaierror) is resolver-side.
            if e.errno in nxdomain_errnos:
                return 'nxdomain'
            return 'ambiguous'
        except (asyncio.TimeoutError, OSError):
            return 'ambiguous'

    @staticmethod
    async def _port_definitely_closed(candidate_url: str) -> bool:
        """#574 — TCP pre-check for ONE scheme candidate's port.

        Returns True ONLY when the port actively REFUSES the connection (RST) — a
        definitive "nothing is listening" that is safe to skip without a browser
        launch. A timeout or any other error is AMBIGUOUS (a slow host, a filtered
        firewall, or a CDN/WAF that stalls a raw connect) and returns False so
        gowitness still gets its chance — we must never drop a live-but-slow
        capture, which is exactly the population typosquats hide behind.
        """
        parsed = urlparse(candidate_url)
        host = parsed.hostname
        if not host:
            return False  # can't tell — let gowitness try
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        try:
            fut = asyncio.open_connection(host, port)
            _, writer = await asyncio.wait_for(fut, timeout=PRECHECK_TIMEOUT)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return False  # open
        except ConnectionRefusedError:
            return True  # definitively dead — safe to skip the browser
        except (asyncio.TimeoutError, OSError):
            return False  # ambiguous — proceed to gowitness (never drop a live host)

    async def _run_gowitness_once(
        self,
        url: str,
        target_dir: str,
        url_hash: str,
        ua_suffix: str,
        chrome_path: Optional[str],
        user_agent_string: Optional[str],
    ) -> Dict[str, Any]:
        """Run gowitness for ONE url, locate + rename the output, hash it.

        Returns ``{ok, error, new_path, new_filename, file_hash, file_size,
        perceptual_hash, has_content, stdout_text}``. ``ok=False`` with a
        populated ``error`` means no usable screenshot file was produced (so the
        caller can fall back to the alternate protocol).
        """
        # Snapshot pre-existing screenshots so a retry never re-picks a prior
        # attempt's already-renamed file when this run produces nothing new.
        try:
            before = {
                f for f in os.listdir(target_dir)
                if f.endswith(('.png', '.jpeg', '.jpg', '.webp'))
            }
        except OSError:
            before = set()

        gowitness_cmd = [
            'gowitness', 'scan', 'single', '--url', url,
            '--screenshot-path', target_dir,
            '--delay', GOWITNESS_DELAY, '--timeout', GOWITNESS_TIMEOUT,
        ]
        if user_agent_string:
            gowitness_cmd.extend(['--chrome-user-agent', user_agent_string])
        if chrome_path:
            gowitness_cmd.extend(['--chrome-path', chrome_path])

        # start_new_session=True makes gowitness a process-group leader so its
        # Chromium children share its pgid and can be killed as a group on
        # timeout (otherwise the Chromium tree orphans to PID 1 and burns CPU).
        process = await asyncio.create_subprocess_exec(
            *gowitness_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        # #571 — register the group so the job watchdog also tears it down if the
        # OUTER per-job timeout fires while this inner communicate() is waiting.
        register_group(process)
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=60)
        except asyncio.TimeoutError:
            await terminate_group(process)
            # Best-effort: remove any partial screenshot gowitness left behind
            # for this run so it can't be mistaken for a real capture later.
            self._remove_partial_outputs(target_dir, before)
            return {'ok': False, 'error': 'timeout', 'stdout_text': ''}

        # Wait briefly for the file to appear
        await asyncio.sleep(1)

        screenshot_file = self._find_recent_screenshot(target_dir, exclude=before)
        if not screenshot_file:
            return {
                'ok': False,
                'error': 'Screenshot file not found after capture',
                'stdout_text': stdout.decode('utf-8', errors='replace') if stdout else '',
            }

        # Rename to a deterministic name with timestamp
        timestamp = int(time.time())
        ext = os.path.splitext(screenshot_file)[1] or '.jpeg'
        new_filename = f"{timestamp}_{url_hash}{ua_suffix}{ext}"
        old_path = os.path.join(target_dir, screenshot_file)
        new_path = os.path.join(target_dir, new_filename)
        os.rename(old_path, new_path)

        return {
            'ok': True,
            'error': None,
            'new_path': new_path,
            'new_filename': new_filename,
            'file_hash': compute_sha256(new_path),
            'file_size': os.path.getsize(new_path),
            'perceptual_hash': self._compute_perceptual_hash(new_path),
            'has_content': self._has_meaningful_content(new_path),
            'stdout_text': stdout.decode('utf-8', errors='replace') if stdout else '',
        }

    async def _capture_screenshot(
        self,
        url: str,
        brand_monitor_id: str,
        typosquat_domain_id: Optional[str],
        output_dir: str,
        user_agent_key: Optional[str] = None,
        user_agent_string: Optional[str] = None,
        storage_driver: str = 'local',
        screenshot_key_prefix: str = 'screenshots',
    ) -> Dict[str, Any]:
        """Capture a single screenshot with hashing and protocol fallback.

        The primary URL is captured first. If it FAILS outright (timeout /
        no file) OR produces a blank image, the alternate-protocol URL
        (http<->https) is attempted before giving up. A per-target
        ``{success: False, error}`` is returned only when every candidate fails.
        """
        subfolder = typosquat_domain_id or 'reference'
        target_dir = os.path.join(
            output_dir, 'brand-monitoring', brand_monitor_id, subfolder
        )
        os.makedirs(target_dir, exist_ok=True)

        try:
            chrome_path = find_chrome_path()
            url_hash = hashlib.sha256(url.encode()).hexdigest()[:12]
            ua_suffix = f"_{user_agent_key}" if user_agent_key else ""

            # #574 — DNS liveness pre-check: a NXDOMAIN host is dead on every
            # scheme, so short-circuit here with ZERO Chromium launches (the
            # majority of registered lookalikes never resolve). Returns the SAME
            # per-target shape as the all-candidates-failed path below so ingestion
            # sees a normal failed capture, not a truncated dict.
            host = urlparse(url).hostname
            # #884 — only an AUTHORITATIVE NXDOMAIN short-circuits with the dead
            # verdict. An 'ambiguous' (transient resolver / EAI_AGAIN) result
            # proceeds to the browser attempt so a resolver outage does not stamp
            # a live registered lookalike as "host does not resolve (DNS)".
            if await self._host_resolves(host) == 'nxdomain':
                return {
                    'target': url,
                    'success': False,
                    'error': 'host does not resolve (DNS)',
                    'filePath': None,
                    'fileHash': None,
                    'perceptualHash': None,
                    'fileSize': 0,
                    'httpStatusCode': None,
                    'pageTitle': None,
                    'hasContent': False,
                    'userAgent': user_agent_key or 'desktop',
                }

            # Candidate URLs: the primary, then the opposite scheme as fallback.
            candidates = [url]
            alt_url = self._alternate_protocol_url(url)
            if alt_url:
                candidates.append(alt_url)

            capture: Optional[Dict[str, Any]] = None  # best result so far
            last_error = 'capture failed'
            for candidate_url in candidates:
                # #574 — TCP-connect pre-check: skip the browser launch only for a
                # port that DEFINITIVELY refuses (RST). An ambiguous timeout falls
                # through to gowitness so a slow/CDN-fronted-but-live host is never
                # dropped; the alternate-protocol retry is likewise only skipped on
                # a definitive refusal.
                if await self._port_definitely_closed(candidate_url):
                    last_error = 'connection refused'
                    if candidate_url != url:
                        print(
                            f"[BrandMonitor:Screenshot] Alternate scheme "
                            f"({candidate_url}) port refused for {url}; skipping"
                        )
                    continue

                attempt = await self._run_gowitness_once(
                    candidate_url, target_dir, url_hash, ua_suffix,
                    chrome_path, user_agent_string,
                )
                if not attempt['ok']:
                    last_error = attempt['error']
                    if candidate_url != url:
                        print(
                            f"[BrandMonitor:Screenshot] Protocol fallback "
                            f"({candidate_url}) failed for {url}: {attempt['error']}"
                        )
                    continue

                attempt['source_url'] = candidate_url
                if capture is None:
                    capture = attempt
                elif attempt['has_content'] and not capture['has_content']:
                    # A real capture beats a previously-held blank one.
                    try:
                        os.remove(capture['new_path'])
                    except OSError:
                        pass
                    capture = attempt
                else:
                    # Redundant (we already have content, or both blank).
                    try:
                        os.remove(attempt['new_path'])
                    except OSError:
                        pass

                if capture['has_content']:
                    break
                # Blank so far — only the alternate protocol remains; loop on.
                if candidate_url != url:
                    print(
                        f"[BrandMonitor:Screenshot] Protocol fallback "
                        f"({candidate_url}) also produced a blank screenshot for {url}"
                    )

            if capture is None:
                # Every candidate (primary + alternate protocol) failed.
                return {
                    'target': url,
                    'success': False,
                    'error': last_error,
                    'filePath': None,
                    'fileHash': None,
                    'perceptualHash': None,
                    'fileSize': 0,
                    'httpStatusCode': None,
                    'pageTitle': None,
                    'hasContent': False,
                    'userAgent': user_agent_key or 'desktop',
                }

            if capture.get('source_url') and capture['source_url'] != url and capture['has_content']:
                print(
                    f"[BrandMonitor:Screenshot] Protocol fallback "
                    f"({capture['source_url']}) succeeded for {url}"
                )

            new_path = capture['new_path']
            new_filename = capture['new_filename']
            file_hash = capture['file_hash']
            file_size = capture['file_size']
            perceptual_hash = capture['perceptual_hash']
            has_content = capture['has_content']

            relative_path = os.path.join(
                'brand-monitoring', brand_monitor_id, subfolder, new_filename
            )

            # Parse HTTP status from gowitness output
            stdout_text = capture['stdout_text']
            http_status = self._extract_http_status(stdout_text)
            page_title = self._extract_page_title(stdout_text)
            final_url = self._extract_final_url(stdout_text)  # #880

            result_entry = {
                'target': url,
                'finalUrl': final_url,  # #880 — post-redirect URL for parking fingerprint
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

            # Cloud WRITE path: when running in GCS mode the agent uploads the
            # final screenshot bytes directly to the bucket so they never traverse
            # the ingestion POST (a 150-image batch would breach Cloud Run's ~32MB
            # request cap). LOCAL mode (storage_driver != 'gcs') skips this branch
            # entirely — gowitness already wrote the shared /app-storage volume.
            #
            # KEY INVARIANT: object key == f"{screenshot_key_prefix}/{relative_path}"
            # which the backend read route reconstructs as
            # normalizeKey("screenshots/" + storedFilePath), storedFilePath being
            # this same relative_path. Upload from relative_path ONLY — never from
            # new_path/output_dir (output_dir already contains "screenshots", which
            # would double the prefix). relative_path is built from generated
            # segments (no "..", no leading slash) so it needs no normalization.
            # The upload runs on new_path — the SETTLED winning file: the
            # candidate loop above already removed any redundant/blank captures
            # and `capture` points at the chosen attempt's final renamed file.
            if storage_driver == 'gcs':
                try:
                    # Lazy import so local agents never need google-cloud-storage.
                    from google.cloud import storage as gcs_storage

                    bucket_name = os.environ.get('STORAGE_GCS_BUCKET', '')
                    if not bucket_name:
                        raise RuntimeError(
                            'storageDriver=gcs but STORAGE_GCS_BUCKET is unset'
                        )

                    object_key = f"{screenshot_key_prefix}/{relative_path}"

                    ext_lower = os.path.splitext(new_path)[1].lower()
                    if ext_lower in ('.jpeg', '.jpg'):
                        content_type = 'image/jpeg'
                    elif ext_lower == '.png':
                        content_type = 'image/png'
                    elif ext_lower == '.webp':
                        content_type = 'image/webp'
                    else:
                        content_type = 'application/octet-stream'

                    # ADC via Cloud Run metadata SA — no key file.
                    client = gcs_storage.Client()
                    blob = client.bucket(bucket_name).blob(object_key)
                    # Keys are timestamp+urlhash unique → create-only is safe; the
                    # agent SA holds objectCreator (no overwrite). Never re-PUT the
                    # same key, so no retry of an identical upload here.
                    blob.upload_from_filename(new_path, content_type=content_type)
                    # NO read-back (blob.exists()) here: the agent SA holds
                    # roles/storage.objectCreator ONLY (create-only, per CLAUDE.md
                    # + infra iam.tf), which does NOT grant storage.objects.get —
                    # so blob.exists() would 403 in cloud, get caught below as an
                    # uploadError, and make the backend drop EVERY successful
                    # upload. Object presence is verified authoritatively on the
                    # backend by IngestionService.screenshotObjectExists()
                    # (ObjectStorageService.exists()), whose SA has objectAdmin —
                    # the correct least-privilege place for the read-back.
                    print(
                        f"[BrandMonitor:Screenshot] Uploaded to "
                        f"gs://{bucket_name}/{object_key}"
                    )
                except Exception as upload_err:
                    # Upload failure does not fail the overall tool — record it on
                    # this entry and keep going. Never retry the same key.
                    print(
                        f"[BrandMonitor:Screenshot] GCS upload failed for {url}: "
                        f"{upload_err}"
                    )
                    result_entry['uploadError'] = str(upload_err)

            return result_entry

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

    def _remove_partial_outputs(self, directory: str, before: set) -> None:
        """Delete screenshot files this run created (anything not in `before`).

        Called only on the timeout branch — `before` is the pre-run snapshot, so
        any image file now present that wasn't before is a partial capture from
        the killed gowitness run. Best-effort and guarded; never touches the
        pre-existing dedup files in `before`.
        """
        try:
            current = {
                f for f in os.listdir(directory)
                if f.endswith(('.png', '.jpeg', '.jpg', '.webp'))
            }
        except OSError:
            return
        for fname in current - before:
            try:
                os.remove(os.path.join(directory, fname))
            except OSError:
                pass

    def _find_recent_screenshot(self, directory: str, exclude: Optional[set] = None) -> Optional[str]:
        """Find the most recently created screenshot file.

        ``exclude`` is a set of filenames to ignore — used by the protocol
        fallback so a retry never re-picks the PRIMARY attempt's already-renamed
        file when the retry itself produced nothing new.
        """
        try:
            img_files = [
                f for f in os.listdir(directory)
                if f.endswith(('.png', '.jpeg', '.jpg', '.webp'))
                and (exclude is None or f not in exclude)
            ]
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
        match = re.search(r'title[=:]\s*"?([^"\n]+)"?', output, re.IGNORECASE)
        if match:
            return match.group(1).strip()[:255]
        return None

    def _extract_final_url(self, output: str) -> Optional[str]:
        """#880 — the FINAL navigated URL (post-redirect) from gowitness output,
        so a redirect to a parking-service host can be fingerprinted. Prefers an
        explicit final_url / location field; otherwise the LAST http(s) URL in the
        output (gowitness logs the resolved URL after following redirects)."""
        m = re.search(r'(?:final[_-]?url|location)[=:]\s*"?(https?://\S+?)"?[\s,\n]', output + '\n', re.IGNORECASE)
        if m:
            return m.group(1).strip()
        urls = re.findall(r'https?://[^\s"\'<>]+', output)
        return urls[-1].strip() if urls else None

    def _is_parked_capture(self, results: List[Dict[str, Any]]) -> bool:
        """#880 — does ANY capture fingerprint a parking / for-sale landing page?
        A parking host (post-redirect final URL) or a for-sale title. Author
        identity of the page, never the pHash divergence (which parking rotation
        trips legitimately)."""
        for r in results:
            title = str(r.get('pageTitle') or '')
            if title and PARKING_TITLE_RE.search(title):
                return True
            final_url = str(r.get('finalUrl') or '')
            host = (urlparse(final_url).hostname or '').lower()
            if host in PARKING_HOSTS:
                return True
        return False

    def _detect_cloaking(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compare screenshots across UA profiles to detect cloaking.

        Only bot-vs-human differences are cloaking candidates. Comparing
        desktop and mobile directly creates false positives for ordinary
        responsive layouts, especially parked-domain pages.
        """
        successful = [r for r in results if r.get('success') and r.get('filePath')]
        human_results = [r for r in successful if r.get('userAgent') in ('desktop', 'mobile')]
        bot_results = [r for r in successful if r.get('userAgent') == 'bot']
        if not human_results or not bot_results:
            return {'detected': False, 'score': 0.0}

        max_distance = 0.0
        used_phash = False

        try:
            import imagehash
            parsed = []
            for r in successful:
                raw = r.get('perceptualHash')
                if raw and raw.startswith('phash:'):
                    parsed.append((r, imagehash.hex_to_hash(raw[len('phash:'):])))

            parsed_humans = [(r, h) for r, h in parsed if r.get('userAgent') in ('desktop', 'mobile')]
            parsed_bots = [(r, h) for r, h in parsed if r.get('userAgent') == 'bot']
            if parsed_humans and parsed_bots:
                used_phash = True
                hash_bit_length = len(parsed_humans[0][1].hash.flatten())
                for _, bot_hash in parsed_bots:
                    for _, human_hash in parsed_humans:
                        hamming = bot_hash - human_hash
                        normalized = hamming / hash_bit_length if hash_bit_length > 0 else 0.0
                        max_distance = max(max_distance, normalized)
        except Exception as e:
            print(f"[BrandMonitor:Screenshot] pHash cloaking comparison failed, falling back to SHA: {e}")

        # Fallback: only compare bot hashes against human hashes. SHA-only
        # differences are noisy, so they are treated as strong only when all
        # bot captures differ from all human captures and no pHash was usable.
        if not used_phash:
            human_hashes = {r.get('fileHash') for r in human_results if r.get('fileHash')}
            bot_hashes = {r.get('fileHash') for r in bot_results if r.get('fileHash')}
            if human_hashes and bot_hashes and human_hashes.isdisjoint(bot_hashes):
                max_distance = 1.0

        detected = max_distance >= CLOAKING_DISTANCE_THRESHOLD
        # #880 — parking / for-sale gate. A for-sale lander rotates ads per request
        # so bot-vs-human pHashes diverge past the threshold, but that is NOT
        # cloaking. Suppress the cloaking signal for a parking-fingerprinted domain
        # and mark it `parked` so the scorer's lifecycle_dampen arms for the
        # sibling alerts. Recall preserved: a genuine bot=phish / human=decoy
        # divergence on a NON-parking host still reports cloaking.
        parked = self._is_parked_capture(results)
        if parked:
            detected = False
        return {'detected': detected, 'score': round(max_distance, 4), 'parked': parked}


def get_tool():
    return BrandMonitorScreenshotTool()

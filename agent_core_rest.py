"""
Core agent implementation - PURE REST API VERSION
No WebSocket dependencies, uses only HTTP REST API for all communication

TODO (BUG-242): Some agent utility scripts (setup_demo.py, test_*.py)
still use synchronous `requests` library. If any sync `requests` call is made from
within the async event loop (e.g., from a tool executed via execute_tool), it will
block the entire asyncio event loop. Consider migrating remaining sync `requests`
usage to `aiohttp` or wrapping in run_in_executor().
"""

import asyncio
import base64
import json
import signal
import aiohttp
from aiohttp import web
from contextvars import ContextVar
from dataclasses import dataclass, field
import os
import glob
from pathlib import Path
from uuid import uuid4
from datetime import datetime, timezone
from plugin_loader import PluginLoader

def parse_env_tags(raw_tags):
    if not raw_tags:
        return []
    return [tag.strip() for tag in raw_tags.split(',') if tag.strip()]


@dataclass
class JobExecutionState:
    job_id: str
    retry_count: int = 0
    output_buffer: list[str] = field(default_factory=list)
    last_output_flush: datetime | None = None
    current_progress: dict | None = None
    flush_requested: bool = False
    flush_fail_count: int = 0

class Agent:
    def __init__(self, config):
        self.config = config
        self.agent_name = os.environ.get('AGENT_NAME') or config['agent']['name']
        self.agent_description = os.environ.get('AGENT_DESCRIPTION') or config['agent'].get('description', self.agent_name)
        self.tags = parse_env_tags(os.environ.get('AGENT_TAGS')) or config['agent'].get('tags', [])
        self.api_url = os.environ.get('AGENT_API_URL') or config['server']['api_url']
        # Per-instance identity (WP4): there is NO static single key. Every
        # running instance enrolls itself via /agents/enroll/tenant using the
        # tenant installer client creds + its own per-instance installationUid,
        # and receives its OWN Agent row + API key. That gives each instance its
        # own currentLoad counter, so throughput scales with instance count.
        self.api_key = None
        self.client_id = os.environ.get('AGENT_CLIENT_ID') or config['server'].get('client_id')
        self.client_secret = os.environ.get('AGENT_CLIENT_SECRET') or config['server'].get('client_secret')
        self.installation_uid = self._get_or_create_installation_uid()
        self.heartbeat_interval = config.get('heartbeat_interval', 30)
        self.poll_interval = config.get('poll_interval', 5)
        self.queue_retry_interval = config.get('queue_retry_interval', 30)
        # Lowered 24h -> 2h (V2 tenant-isolation): credential-bearing spool files
        # must not linger a full day on the shared pool. 2h is ample resend
        # resilience for a transient backend outage while bounding residue.
        self.queue_result_max_age_hours = config.get('queue_result_max_age_hours', 2)
        self.runtime_started_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

        self.running = False
        # R4 graceful drain: set on SIGTERM/SIGINT. Stops claiming new jobs and
        # wakes the main loop so it can exit promptly after releasing in-flight
        # claimed jobs back to the queue.
        self._draining = False
        self._shutdown_event: asyncio.Event | None = None
        self.plugin_loader = PluginLoader(config, agent=self)

        # Pub/Sub configuration — push-only delivery (cloud sub is Terraform-owned,
        # delivers via OIDC POST to /pubsub/push). The GET /agents/poll/jobs poll is
        # the always-on backstop (Postgres SKIP LOCKED is the source of truth).
        pubsub_config = config.get('pubsub', {})
        self.project_id = os.environ.get('GCP_PROJECT_ID') or pubsub_config.get('project_id', 'xasm-local')
        self.http_port = int(os.environ.get('AGENT_HTTP_PORT', '8080'))
        self._job_notify_queue = asyncio.Queue()
        self._loop = None

        # Output streaming and progress tracking (per-job)
        self.output_buffer_max_size = 100 * 1024  # 100KB before flush
        # BUG-090: Flush failure tracking and buffer hard limit
        self._flush_max_retries = 5
        self._output_buffer_hard_limit = 1024 * 1024  # 1MB
        self._current_execution_state: ContextVar[JobExecutionState | None] = ContextVar(
            'current_execution_state',
            default=None,
        )
        self._active_jobs: dict[str, JobExecutionState] = {}
        self._active_job_tasks: dict[str, asyncio.Task] = {}

        # Bounded job concurrency: a Pub/Sub notification flood can otherwise
        # fan out one heavy tool subprocess per claimed job (nuclei, headless
        # chromium, ...) and breach the container's 1 GiB memory limit — the
        # OOM-killed agent restarts and releases its in-flight jobs back to the
        # queue, interrupting long scans. The default of 3 matches the agent's
        # typical concurrency limit; lower it (e.g. AGENT_MAX_CONCURRENT_JOBS=2)
        # via env on memory-constrained hosts. Excess claimed jobs simply wait
        # their turn on the semaphore.
        self.max_concurrent_jobs = int(os.environ.get('AGENT_MAX_CONCURRENT_JOBS', '3'))
        self._job_semaphore = asyncio.Semaphore(self.max_concurrent_jobs)

        # BUG-088: Reusable aiohttp session (lazy-initialized)
        self._session = None
        self._tools_registered = False
        self._last_queue_retry = datetime.min
        self._last_completion_status = None

    @staticmethod
    def _installation_uid_path():
        return Path('/var/lib/xasm-agent/installation-uid')

    def _get_or_create_installation_uid(self):
        """Resolve this instance's per-instance installation UID.

        Each distinct value maps to its OWN Agent row server-side, so the UID
        must be unique per concurrently-running instance (that is what unlocks
        instances × concurrencyLimit throughput):

          - AGENT_INSTALLATION_UID — explicit override. Local docker-compose
            sets a distinct, stable value per agent service.
          - K_REVISION (Cloud Run) — combined with a uuid so each autoscaled
            instance of a revision gets its own row, while the K_REVISION prefix
            keeps the rows attributable to the deploy.
          - else — a uuid persisted to disk so a process restart reuses the
            same row (standalone/local execution without an explicit override).
        """
        env_uid = os.environ.get('AGENT_INSTALLATION_UID')
        if env_uid:
            return env_uid

        k_revision = os.environ.get('K_REVISION')
        if k_revision:
            return f"{k_revision}-{uuid4()}"

        uid_path = self._installation_uid_path()
        try:
            if uid_path.exists():
                stored_uid = uid_path.read_text().strip()
                if stored_uid:
                    return stored_uid
        except Exception as e:
            print(f"[Enroll] Failed to read installation UID: {e}")

        new_uid = f"inst_{uuid4()}"
        try:
            uid_path.parent.mkdir(parents=True, exist_ok=True)
            uid_path.write_text(new_uid)
        except Exception as e:
            print(f"[Enroll] Failed to persist installation UID: {e}")

        return new_uid

    def _auth_headers(self):
        """Build request headers with this instance's enrolled API key."""
        headers = {}
        if self.api_key:
            headers['X-API-Key'] = self.api_key
        return headers

    async def _get_session(self):
        """Get or create a reusable aiohttp ClientSession"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def ensure_runtime_key(self):
        """Obtain this instance's per-instance API key via tenant enrollment.

        Always calls /agents/enroll/tenant: the backend upserts the Agent row
        keyed on installationUid (idempotent) and returns a freshly-issued,
        installationUid-prefixed key for THIS instance's own row. A no-op once a
        key is already held — re-enrollment only happens after an auth failure.
        """
        if self.api_key:
            return True

        if not (self.client_id and self.client_secret):
            print("[Enroll] No tenant installer credentials configured (AGENT_CLIENT_ID/AGENT_CLIENT_SECRET)")
            return False

        try:
            session = await self._get_session()
            timeout = aiohttp.ClientTimeout(total=15)
            async with session.post(
                f"{self.api_url}/agents/enroll/tenant",
                json={
                    'clientId': self.client_id,
                    'clientSecret': self.client_secret,
                    'installationUid': self.installation_uid,
                    'requestedName': self.agent_name,
                    'description': self.agent_description,
                    'tags': self.tags,
                },
                timeout=timeout,
            ) as response:
                if 200 <= response.status < 300:
                    payload = await response.json()
                    self._set_runtime_key(payload.get('apiKey'))
                    agent = payload.get('agent') or {}
                    self.agent_name = agent.get('name', self.agent_name)
                    self.agent_description = agent.get('description', self.agent_description)
                    self.tags = agent.get('tags') or self.tags
                    print(
                        f"[Enroll] ✓ Tenant-enrolled instance {self.agent_name} "
                        f"(installation UID: {self.installation_uid})"
                    )
                    return True

                body = await response.text()
                print(f"[Enroll] Tenant enrollment failed with status {response.status}: {body[:200]}")
                return False
        except Exception as e:
            print(f"[Enroll] Tenant enrollment error: {e}")
            return False

    def _set_runtime_key(self, api_key):
        """Adopt the enrolled per-instance key and share it with the credential
        helper so per-tool ProviderQuotaService checkouts authenticate as THIS
        same instance (one identity for jobs and for credential leases)."""
        self.api_key = api_key
        try:
            from lib.integration_credentials import set_runtime_api_key
            set_runtime_api_key(api_key)
        except Exception as e:
            print(f"[Enroll] Could not publish runtime key to credential helper: {e}")

    async def run(self):
        """Main agent loop"""
        print(f"\n{'='*60}")
        print(f"ASM Platform Agent - REST API Mode")
        print(f"{'='*60}")
        print(f"Agent: {self.agent_name}")
        print(f"Description: {self.agent_description}")
        print(f"Tags: {', '.join(self.tags)}")
        print(f"Server: {self.api_url}")
        print(f"Pub/Sub: project={self.project_id}, delivery=push (/pubsub/push) + poll backstop")
        print()

        # Load plugins
        self.plugin_loader.load_plugins()
        print(f"Loaded {len(self.plugin_loader.plugins)} tools")
        print()

        self.running = True
        self._loop = asyncio.get_running_loop()
        self._shutdown_event = asyncio.Event()

        # R4: register a SIGTERM (Cloud Run scale-in / revision swap) + SIGINT
        # handler. On signal we stop claiming new jobs and release each in-flight
        # claimed job back to the queue (status->PENDING, retryCount++) so a
        # reclaimed instance never silently loses work. Falls back gracefully if
        # the platform cannot install signal handlers (e.g. non-main thread).
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                self._loop.add_signal_handler(
                    sig,
                    lambda s=sig: asyncio.ensure_future(self._handle_shutdown_signal(s)),
                )
            except (NotImplementedError, RuntimeError, ValueError) as e:
                print(f"[Agent] Could not install handler for {sig!r}: {e}")

        await self.ensure_runtime_key()

        # Process any queued results from previous runs
        await self.process_queued_results()

        # Register tools with platform
        self._tools_registered = await self.register_tools()
        # Send a startup heartbeat before polling so the backend can reconcile
        # jobs left RUNNING by a previous container/process instance.
        await self.send_heartbeat()

        # Start HTTP server (push endpoint + health check)
        http_task = asyncio.create_task(self._start_http_server())
        http_task.add_done_callback(
            lambda t: t.exception() and print(f"[HTTP] Server died: {t.exception()}")
        )

        # Job notifications arrive via Pub/Sub push (POST /pubsub/push). The
        # GET /agents/poll/jobs poll in main_loop is the always-on backstop.

        # Start periodic nuclei template update (every 24h)
        template_update_task = asyncio.create_task(self._periodic_template_update())

        # Start main loop
        await self.main_loop()

        # Cancel template update task on shutdown
        template_update_task.cancel()
        try:
            await template_update_task
        except asyncio.CancelledError:
            pass

    async def _start_http_server(self):
        """Start HTTP server for Pub/Sub push delivery and health checks.

        Pub/Sub push subscription delivers job notifications via HTTP POST to
        /pubsub/push (cloud: Terraform-owned PUSH sub w/ OIDC; local: pubsub-init
        creates a push sub targeting this endpoint). The GET /agents/poll/jobs
        poll in main_loop is the always-on dispatch backstop.
        """
        app = web.Application()
        app.router.add_get('/health', self._handle_health)
        app.router.add_post('/pubsub/push', self._handle_pubsub_push)
        app.router.add_get('/cache-stats', self._handle_cache_stats)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', self.http_port)
        await site.start()
        print(f"[HTTP] Server listening on port {self.http_port} (push: /pubsub/push, health: /health)")

    async def _handle_health(self, request):
        """Health check endpoint for Cloud Run / load balancers"""
        return web.json_response({
            'status': 'healthy',
            'agent': self.agent_name,
            'running': self.running,
            'current_jobs': sorted(self._active_jobs.keys()),
            'current_job_count': len(self._active_jobs),
        })

    async def _handle_cache_stats(self, request):
        """Cache observability — surfaces the per-process upstream cache
        counters (size, hits, misses, stales) for Phase 2B socint cost
        control. Five agent containers = five independent caches; query
        each one to get a cluster-wide picture."""
        try:
            from lib.upstream_cache import upstream_cache
            stats = await upstream_cache.stats()
            return web.json_response({'agent': self.agent_name, 'cache': stats})
        except Exception as e:
            return web.json_response(
                {'agent': self.agent_name, 'error': str(e)}, status=500,
            )

    async def _handle_pubsub_push(self, request):
        """Handle Pub/Sub push delivery — same signal as pull, different transport"""
        try:
            envelope = await request.json()
            # Pub/Sub push format: {"message": {"data": "<base64>", "messageId": "..."}, "subscription": "..."}
            message = envelope.get('message', {})
            if message.get('data'):
                data = json.loads(base64.b64decode(message['data']).decode('utf-8'))
                print(f"[PubSub/Push] Received notification for job {data.get('jobId', 'unknown')[:8]}")

            # Signal the main loop — same queue as pull subscriber
            self._job_notify_queue.put_nowait(True)
            return web.json_response({'status': 'ok'})
        except Exception as e:
            print(f"[PubSub/Push] Error processing message: {e}")
            # Return 200 anyway to ACK — we don't want Pub/Sub retrying notifications
            return web.json_response({'status': 'error', 'detail': str(e)})

    async def register_tools(self):
        """Register available tools with the platform via REST API"""
        try:
            tools_list = self.plugin_loader.list_tools()
            print(f"[ToolReg] Registering {len(tools_list)} tools with platform...")

            # Format tools for backend
            tools_payload = [
                {
                    'name': tool['name'],
                    'schema': tool['schema'],
                    'metadata': tool.get('metadata', {}),
                }
                for tool in tools_list
            ]

            session = await self._get_session()
            timeout = aiohttp.ClientTimeout(total=10)
            async with session.post(
                f"{self.api_url}/agents/tools/register",
                json={'tools': tools_payload},
                headers=self._auth_headers(),
                timeout=timeout
            ) as response:
                if 200 <= response.status < 300:
                    print(f"[ToolReg] ✓ Successfully registered {len(tools_list)} tools")
                    return True

                body = await response.text()
                print(f"[ToolReg] ⚠ Registration returned {response.status}: {body[:200]}")
                return False

        except Exception as e:
            print(f"[ToolReg] Failed to register tools: {e}")
            return False

    async def main_loop(self):
        """Main agent loop - waits for Pub/Sub notifications, claims and executes jobs"""
        print(f"\n{'='*60}")
        print(f"Agent running - Pub/Sub notification mode")
        print(f"  Fallback poll every {self.poll_interval}s if no notifications")
        print(f"{'='*60}\n")

        last_heartbeat = datetime.now()

        while self.running:
            try:
                # R4: a SIGTERM/SIGINT sets _draining; stop claiming and exit so
                # the drain (release of in-flight jobs) can finish in run().
                if self._draining:
                    print("[Agent] Drain requested — exiting main loop, no new claims")
                    break

                await self.ensure_runtime_key()

                if not self._tools_registered:
                    self._tools_registered = await self.register_tools()

                # Send heartbeat if interval passed
                now = datetime.now()
                if (now - last_heartbeat).total_seconds() >= self.heartbeat_interval:
                    await self.send_heartbeat()
                    last_heartbeat = now

                # Results are written to /tmp/agent_queue before completion is
                # posted. If the backend restarts between tool completion and
                # the POST, retry from the live loop instead of waiting for an
                # agent container restart.
                if (now - self._last_queue_retry).total_seconds() >= self.queue_retry_interval:
                    if glob.glob("/tmp/agent_queue/result_*.json"):
                        await self.process_queued_results()
                    self._last_queue_retry = now

                # Wait for Pub/Sub notification OR timeout (fallback poll)
                try:
                    await asyncio.wait_for(
                        self._job_notify_queue.get(),
                        timeout=self.poll_interval
                    )
                    # Drain any additional queued notifications
                    while not self._job_notify_queue.empty():
                        try:
                            self._job_notify_queue.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                except asyncio.TimeoutError:
                    pass  # Fallback: poll anyway on timeout

                # A shutdown signal may have arrived while we were waiting.
                if self._draining:
                    print("[Agent] Drain requested during poll wait — exiting main loop")
                    break

                # Claim and execute jobs via existing REST endpoint
                jobs = await self.poll_jobs()

                if jobs:
                    print(f"[JobPoll] Received {len(jobs)} job(s)")
                    for job in jobs:
                        self._start_job_task(job)

            except KeyboardInterrupt:
                print("\n[Agent] Received shutdown signal")
                self._draining = True
                break
            except Exception as e:
                print(f"[Agent] Error in main loop: {e}")
                await asyncio.sleep(10)

        # R4: main loop exited — if this was a drain, release in-flight jobs.
        if self._draining:
            await self._drain_in_flight_jobs()

    async def _handle_shutdown_signal(self, sig):
        """R4: SIGTERM/SIGINT handler — begin graceful drain.

        Flips the drain flag so the main loop stops claiming new jobs, then
        wakes the loop (which is usually blocked on the notify-queue wait) so it
        exits promptly and releases in-flight claimed jobs. Idempotent: a second
        signal is a no-op while a drain is already in progress.
        """
        if self._draining:
            return
        print(f"\n[Agent] Received {sig!r} — beginning graceful drain")
        self._draining = True
        self.running = False
        # Wake the main loop's `wait_for(self._job_notify_queue.get(), ...)`.
        try:
            self._job_notify_queue.put_nowait(True)
        except Exception:
            pass

    async def _drain_in_flight_jobs(self):
        """R4: release every in-flight claimed job back to the queue on shutdown.

        Cancels each running job task, then asks the backend to requeue the job
        (status->PENDING, retryCount++ per BUG-032) via POST /jobs/:id/release so
        a surviving sibling agent re-claims it. retryCount++ also invalidates a
        late `complete` if the tool happened to finish in the drain window, so
        there is no double-ingest.
        """
        job_ids = list(self._active_job_tasks.keys())
        if not job_ids:
            print("[Drain] No in-flight jobs to release")
            return

        print(f"[Drain] Releasing {len(job_ids)} in-flight job(s) back to the queue")
        for job_id in job_ids:
            task = self._active_job_tasks.get(job_id)
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    print(f"[Drain] Job {job_id[:8]} task raised during cancel: {e}")
            released = await self.release_job(job_id)
            if released:
                print(f"[Drain] ✓ Released job {job_id[:8]} back to PENDING")
            else:
                print(f"[Drain] ⚠ Release no-op for job {job_id[:8]} (already terminal/reassigned)")

    async def release_job(self, job_id):
        """R4: release a claimed job back to the queue via REST (graceful drain)."""
        try:
            url = f"{self.api_url}/agents/jobs/{job_id}/release"
            session = await self._get_session()
            timeout = aiohttp.ClientTimeout(total=10)
            async with session.post(
                url,
                headers=self._auth_headers(),
                timeout=timeout,
            ) as response:
                if 200 <= response.status < 300:
                    body = await response.json()
                    return bool(body.get('released'))
                text = await response.text()
                print(f"[Release] ⚠ Failed for job {job_id[:8]}: {response.status} - {text[:200]}")
                return False
        except Exception as e:
            print(f"[Release] ✗ Error for job {job_id[:8]}: {e}")
            return False

    def _start_job_task(self, job):
        """Start a claimed job without blocking the main polling loop."""
        job_id = job['id']
        existing_task = self._active_job_tasks.get(job_id)
        if existing_task and not existing_task.done():
            print(f"[JobPoll] Job {job_id[:8]} already running locally, skipping duplicate dispatch")
            return

        task = asyncio.create_task(self.execute_job(job), name=f"job-{job_id[:8]}")
        self._active_job_tasks[job_id] = task
        task.add_done_callback(lambda finished_task, claimed_job_id=job_id: self._finish_job_task(claimed_job_id, finished_task))

    def _finish_job_task(self, job_id, task):
        """Clean up bookkeeping and surface background job failures."""
        self._active_job_tasks.pop(job_id, None)
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"[JobTask] Background task for job {job_id[:8]} crashed: {e}")

    def _get_execution_state(self, job_id: str | None = None) -> JobExecutionState | None:
        if job_id:
            return self._active_jobs.get(job_id)
        return self._current_execution_state.get()

    async def send_heartbeat(self):
        """Send heartbeat via REST API"""
        try:
            payload = {
                'activeJobIds': list(self._active_jobs.keys()),
                'activeJobCount': len(self._active_jobs),
                'runtimeStartedAt': self.runtime_started_at,
            }
            session = await self._get_session()
            timeout = aiohttp.ClientTimeout(total=5)
            async with session.post(
                f"{self.api_url}/agents/heartbeat",
                json=payload,
                headers=self._auth_headers(),
                timeout=timeout
            ) as response:
                if 200 <= response.status < 300:
                    print(f"[Heartbeat] ✓ Sent")
                else:
                    print(f"[Heartbeat] ⚠ Response: {response.status}")
        except Exception as e:
            print(f"[Heartbeat] Error: {e}")

    def append_output(self, output: str):
        """Append output to buffer for streaming (called from sync tool context)"""
        state = self._get_execution_state()
        if not state:
            print(f"[OutputStream] ⚠ Dropping output without active job context: {output[:120]}")
            return

        state.output_buffer.append(output)

        # BUG-090: Enforce hard limit on buffer size
        buffer_size = sum(len(s) for s in state.output_buffer)
        if buffer_size >= self._output_buffer_hard_limit:
            # Truncate to most recent 10% of entries
            keep_count = max(1, len(state.output_buffer) // 10)
            dropped = len(state.output_buffer) - keep_count
            state.output_buffer = state.output_buffer[-keep_count:]
            print(f"[OutputStream] ⚠ Buffer for job {state.job_id[:8]} exceeded 1MB hard limit, dropped {dropped} oldest entries")

        # BUG-068: Signal flush request safely from sync context
        # Instead of asyncio.create_task() which fails without a running loop,
        # set a flag that the heartbeat loop checks every 15s
        if buffer_size >= self.output_buffer_max_size:
            state.flush_requested = True
            # Try to schedule flush on the running loop if available
            try:
                loop = asyncio.get_running_loop()
                loop.call_soon_threadsafe(
                    lambda: asyncio.ensure_future(self.flush_output_buffer(state=state))
                )
            except RuntimeError:
                # No running loop — flush_requested flag will be picked up by heartbeat loop
                pass

    async def flush_output_buffer(self, force=False, state: JobExecutionState | None = None):
        """Flush output buffer to backend"""
        state = state or self._get_execution_state()
        if not state or not state.output_buffer:
            return

        if not force:
            # Rate limit: don't flush more than once per 5 seconds
            if state.last_output_flush:
                elapsed = (datetime.now() - state.last_output_flush).total_seconds()
                if elapsed < 5:
                    return

        try:
            output_text = '\n'.join(state.output_buffer)
            if state.job_id and output_text:
                session = await self._get_session()
                timeout = aiohttp.ClientTimeout(total=10)
                async with session.post(
                    f"{self.api_url}/agents/jobs/{state.job_id}/output",
                    json={'output': output_text},
                    headers=self._auth_headers(),
                    timeout=timeout
                ) as response:
                    # BUG-508: accept any 2xx. NestJS @Post returns 201 Created
                    # by default so the old `== 200` check turned every
                    # successful incremental flush into a retried-then-dropped
                    # buffer, which showed up as "Flush returned status 201"
                    # spam and lost incremental output for long-running tools.
                    if 200 <= response.status < 300:
                        print(f"[OutputStream] ✓ Flushed {len(output_text)} chars for job {state.job_id[:8]} (HTTP {response.status})")
                        state.output_buffer = []
                        state.last_output_flush = datetime.now()
                        # BUG-090: Reset failure counter on success
                        state.flush_fail_count = 0
                        state.flush_requested = False
                    else:
                        raise Exception(f"Flush returned status {response.status}")
        except Exception as e:
            # BUG-090: Track consecutive flush failures
            state.flush_fail_count += 1
            print(f"[OutputStream] ⚠ Flush error for job {state.job_id[:8]} (attempt {state.flush_fail_count}/{self._flush_max_retries}): {e}")

            if state.flush_fail_count >= self._flush_max_retries:
                dropped_count = len(state.output_buffer)
                dropped_size = sum(len(s) for s in state.output_buffer)
                state.output_buffer = []
                state.flush_fail_count = 0
                state.flush_requested = False
                print(f"[OutputStream] ⚠ Dropped buffer for job {state.job_id[:8]} after {self._flush_max_retries} consecutive failures ({dropped_count} entries, {dropped_size} bytes)")

    def report_progress(self, current_operation: str, current_target: str = None,
                       items_processed: int = None, total_items: int = None):
        """Report progress for current job"""
        state = self._get_execution_state()
        if not state:
            print(f"[Progress] ⚠ Ignoring progress update without active job context: {current_operation}")
            return

        state.current_progress = {
            'currentOperation': current_operation,
            'currentTarget': current_target,
            'itemsProcessed': items_processed,
            'totalItems': total_items,
        }
        # Progress is sent with next heartbeat

    async def poll_jobs(self):
        """Poll for available jobs via REST API"""
        try:
            session = await self._get_session()
            timeout = aiohttp.ClientTimeout(total=10)
            params = {}
            if self.tags:
                params['tags'] = ','.join(self.tags)
            async with session.get(
                f"{self.api_url}/agents/poll/jobs",
                params=params,
                headers=self._auth_headers(),
                timeout=timeout
            ) as response:
                if response.status == 200:
                    return await response.json()
                if response.status == 401:
                    # This instance's key was rejected (row reaped / backend
                    # re-seeded). Drop it so the next loop re-enrolls and gets a
                    # fresh per-instance key + row.
                    print("[JobPoll] 401 — dropping stale runtime key, will re-enroll")
                    self._set_runtime_key(None)
                return []
        except Exception as e:
            print(f"[JobPoll] Error: {e}")
            return []

    async def execute_job(self, job):
        """Execute a claimed job, bounded by the concurrency semaphore.

        Claimed jobs beyond max_concurrent_jobs wait here until a slot frees
        up — this caps peak memory under a notification flood (see __init__).
        """
        job_id = job['id']
        if self._job_semaphore.locked():
            print(f"[ExecuteJob] Job {job_id[:8]} waiting for a free execution slot "
                  f"(cap: {self.max_concurrent_jobs} concurrent jobs)")
        async with self._job_semaphore:
            await self._execute_job_inner(job)

    async def _execute_job_inner(self, job):
        """Execute a claimed job"""
        job_id = job['id']
        tool_name = job['toolName']
        parameters = job['parameters']
        retry_count = job.get('retryCount', 0)  # BUG-032: Capture retryCount for version checking

        # Inject job_id for output file naming
        parameters['_job_id'] = job_id

        print(f"\n{'='*60}")
        print(f"→ Executing job {job_id[:8]}")
        print(f"  Tool: {tool_name}")
        print(f"  Target: {parameters.get('target', 'N/A')}")
        print(f"  Retry Count: {retry_count}")  # BUG-032: Log retryCount
        print(f"{'='*60}")

        # Job is already claimed by poll endpoint (atomic claiming)
        # No need to claim again - proceed directly to execution

        state = JobExecutionState(job_id=job_id, retry_count=retry_count)
        self._active_jobs[job_id] = state
        state_token = self._current_execution_state.set(state)

        # WP6 — publish the active job id so money/secrets-path calls send
        # X-Job-Id. A BOOTSTRAP agent's backend re-derives the billing tenant
        # from this job (ownership-verified); a dedicated agent ignores it.
        try:
            from lib.integration_credentials import set_current_job_id
            set_current_job_id(job_id)
        except Exception:
            pass

        # Start background heartbeat during execution
        heartbeat_task = asyncio.create_task(self.execution_heartbeat_loop(state))

        result = None
        tool_success = False

        try:
            # Execute the plugin (plugin can now call report_progress)
            print(f"[ExecuteJob] Starting tool execution: {tool_name}")
            try:
                result = await self.plugin_loader.execute_tool(tool_name, parameters)
                print(f"[ExecuteJob] Tool execution completed: {tool_name}")
            except Exception as tool_error:
                print(f"[ExecuteJob] ✗ Tool execution failed: {tool_error}")
                import traceback
                traceback.print_exc()
                raise  # Re-raise to be caught by outer exception handler

            tool_success = True
            if isinstance(result, dict) and 'success' in result:
                tool_success = bool(result.get('success'))

            # Persist the result before any network flush/completion call. If
            # the container is restarted or the task is cancelled in the small
            # window after the tool returns, process_queued_results() will
            # replay this result instead of letting the backend hit timeout.
            await asyncio.shield(
                self.queue_result(job_id, result, success=tool_success, retry_count=retry_count)
            )

            # Send completion (BUG-032: Pass retryCount for version checking)
            print(f"[DEBUG] About to call complete_job for {job_id[:8]} with retryCount={retry_count}")
            completion_sent = await self.complete_job(job_id, result, success=tool_success, retry_count=retry_count)
            print(f"[DEBUG] complete_job returned: {completion_sent}")

            # Flush any remaining output only after terminal completion. Output
            # streaming is useful for the UI, but completion is the durability
            # boundary that prevents false backend timeouts.
            await self.flush_output_buffer(force=True, state=state)

            if completion_sent:
                if tool_success:
                    print(f"✓ Job {job_id[:8]} completed successfully")
                else:
                    print(f"✗ Job {job_id[:8]} completed with tool failure")

                # Wait for findings acknowledgment before cleanup
                ack_received = await self.acknowledge_findings(job_id)

                if ack_received:
                    # Only cleanup after ACK confirmation
                    await self.cleanup_output_file(result)
                    await self.cleanup_queue_file(job_id)
                else:
                    print(f"[FindingsACK] ⚠ ACK failed for job {job_id[:8]}, keeping queue file for retry")
                    # Keep queue file for retry, but still cleanup output file
                    await self.cleanup_output_file(result)
            else:
                print(f"[Completion] ⚠ Completion failed for job {job_id[:8]}, keeping queue file for retry")
                # Keep both files for retry
                pass

        except asyncio.CancelledError:
            print(f"[ExecuteJob] Job task cancelled for {job_id[:8]} - preserving result for replay")
            await self.flush_output_buffer(force=True, state=state)
            if result is not None:
                await asyncio.shield(
                    self.queue_result(job_id, result, success=tool_success, retry_count=retry_count)
                )
            raise
        except Exception as e:
            print(f"✗ Job {job_id[:8]} failed: {e}")
            await self.flush_output_buffer(force=True, state=state)
            # BUG-032: Include retryCount in failure case too
            await asyncio.shield(
                self.queue_result(job_id, str(e), success=False, retry_count=retry_count)
            )
            await self.complete_job(job_id, str(e), success=False, retry_count=retry_count)
            # Don't cleanup on failure - keep queue file for retry
        finally:
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass
            self._active_jobs.pop(job_id, None)
            self._current_execution_state.reset(state_token)
            try:
                from lib.integration_credentials import set_current_job_id
                set_current_job_id(None)
            except Exception:
                pass

    async def claim_job(self, job_id):
        """Claim a job via REST API"""
        try:
            session = await self._get_session()
            timeout = aiohttp.ClientTimeout(total=10)
            async with session.post(
                f"{self.api_url}/agents/jobs/{job_id}/claim",
                headers=self._auth_headers(),
                timeout=timeout
            ) as response:
                return 200 <= response.status < 300
        except Exception as e:
            print(f"[Claim] Error: {e}")
            return False

    async def execution_heartbeat_loop(self, state: JobExecutionState):
        """Send heartbeats during job execution with progress updates"""
        job_id = state.job_id
        print(f"[ExecHeartbeat] Starting for job {job_id[:8]}")
        try:
            while True:
                try:
                    # Build heartbeat payload with progress if available
                    payload = {
                        'jobId': job_id,
                        'activeJobIds': list(self._active_jobs.keys()),
                        'activeJobCount': len(self._active_jobs),
                        'runtimeStartedAt': self.runtime_started_at,
                    }
                    if state.current_progress:
                        payload['progress'] = state.current_progress

                    session = await self._get_session()
                    timeout = aiohttp.ClientTimeout(total=5)
                    async with session.post(
                        f"{self.api_url}/agents/heartbeat",
                        json=payload,
                        headers=self._auth_headers(),
                        timeout=timeout
                    ) as response:
                        if response.status == 200:
                            if state.current_progress:
                                print(f"[ExecHeartbeat] ✓ Job {job_id[:8]} - {state.current_progress.get('currentOperation', 'working')}")
                            else:
                                print(f"[ExecHeartbeat] ✓ Job {job_id[:8]}")

                    # BUG-068: Check flush flag set by append_output()
                    if state.flush_requested:
                        await self.flush_output_buffer(state=state)

                    # Also flush output buffer periodically
                    await self.flush_output_buffer(state=state)

                    await asyncio.sleep(15)
                except Exception as e:
                    print(f"[ExecHeartbeat] Error: {e}")
                    await asyncio.sleep(15)
        except asyncio.CancelledError:
            print(f"[ExecHeartbeat] Stopped for job {job_id[:8]}")
            raise

    async def complete_job(self, job_id, output, success=True, retry_count=None):
        """Mark job as complete via REST API (BUG-032: Added retry_count parameter)"""
        try:
            self._last_completion_status = None
            url = f"{self.api_url}/agents/jobs/{job_id}/complete"
            print(f"[DEBUG] Sending completion to: {url}")
            print(f"[DEBUG] Output keys: {list(output.keys()) if isinstance(output, dict) else 'not a dict'}")
            print(f"[DEBUG] Findings count: {len(output.get('findings', [])) if isinstance(output, dict) else 'N/A'}")
            print(f"[DEBUG] Retry Count: {retry_count if retry_count is not None else 'not provided'}")  # BUG-032

            # BUG-032: Include retryCount in request payload for version checking
            payload = {'output': output, 'success': success}
            if retry_count is not None:
                payload['retryCount'] = retry_count

            session = await self._get_session()
            timeout = aiohttp.ClientTimeout(total=180)  # 3 minutes for large outputs (nuclei with 300+ findings)
            async with session.post(
                url,
                json=payload,
                headers=self._auth_headers(),
                timeout=timeout
            ) as response:
                status = response.status
                self._last_completion_status = status
                headers = dict(response.headers)
                body = await response.text()
                print(f"[DEBUG] Response status: {status}")
                print(f"[DEBUG] Response headers: {headers}")
                print(f"[DEBUG] Response body: {body[:300]}")

                if 200 <= status < 300:
                    print(f"✓ Job {job_id[:8]} completion sent - Status: {status}")
                    return True
                else:
                    print(f"✗ Job completion failed: {status} - {body[:200]}")
                    return False
        except Exception as e:
            self._last_completion_status = None
            print(f"✗ Failed to complete job {job_id[:8]}: {e}")
            import traceback
            traceback.print_exc()
            return False

    async def acknowledge_findings(self, job_id):
        """Acknowledge findings ingestion via REST API"""
        try:
            url = f"{self.api_url}/agents/jobs/{job_id}/findings/ack"
            print(f"[FindingsACK] Sending acknowledgment for job {job_id[:8]}")

            session = await self._get_session()
            timeout = aiohttp.ClientTimeout(total=30)
            async with session.post(
                url,
                headers=self._auth_headers(),
                timeout=timeout
            ) as response:
                if 200 <= response.status < 300:
                    print(f"[FindingsACK] ✓ Acknowledged for job {job_id[:8]}")
                    return True
                else:
                    body = await response.text()
                    print(f"[FindingsACK] ⚠ Failed: {response.status} - {body[:200]}")
                    return False
        except Exception as e:
            print(f"[FindingsACK] ✗ Error for job {job_id[:8]}: {e}")
            return False

    async def queue_result(self, job_id, result, success=True, retry_count=None):
        """Queue result for resilience (BUG-032: Added retry_count parameter)"""
        try:
            queue_dir = "/tmp/agent_queue"
            os.makedirs(queue_dir, exist_ok=True)
            # V2 tenant-isolation: a result can carry session credentials (e.g. the
            # login tools' filtered cookies). On the shared bootstrap pool these
            # spool files would otherwise sit world-readable in /tmp across other
            # tenants' jobs. Restrict to owner-only (defense vs other containers)
            # and rely on the bounded max-age sweep to cap residue lifetime. Full
            # cross-tenant isolation within one process needs per-tenant pools.
            try:
                os.chmod(queue_dir, 0o700)
            except OSError:
                pass

            queue_file = f"{queue_dir}/result_{job_id[:8]}.json"
            with open(queue_file, 'w') as f:
                json.dump({
                    'job_id': job_id,
                    'result': result,
                    'success': success,
                    'retry_count': retry_count,  # BUG-032: Store retryCount in queue
                    'timestamp': datetime.now().isoformat()
                }, f)
            try:
                os.chmod(queue_file, 0o600)
            except OSError:
                pass
            print(f"[Queue] Result queued: {queue_file}")
        except Exception as e:
            print(f"[Queue] Warning: Could not queue result: {e}")

    async def cleanup_output_file(self, result):
        """Cleanup tool output file"""
        try:
            output_file = result.get('output_file')
            if output_file and os.path.exists(output_file):
                os.remove(output_file)
                print(f"[Cleanup] ✓ Removed output file")
        except Exception as e:
            print(f"[Cleanup] Warning: {e}")

    async def cleanup_queue_file(self, job_id):
        """Cleanup queue file after successful send"""
        try:
            queue_file = f"/tmp/agent_queue/result_{job_id[:8]}.json"
            if os.path.exists(queue_file):
                os.remove(queue_file)
                print(f"[Cleanup] ✓ Removed queue file")
        except Exception as e:
            print(f"[Cleanup] Warning: {e}")

    async def process_queued_results(self):
        """Process any queued results from previous runs"""
        try:
            queue_dir = "/tmp/agent_queue"
            if not os.path.exists(queue_dir):
                return

            queue_files = glob.glob(f"{queue_dir}/result_*.json")
            if not queue_files:
                return

            print(f"[Queue] Found {len(queue_files)} queued result(s) from previous runs")

            for queue_file in queue_files:
                try:
                    with open(queue_file, 'r') as f:
                        data = json.load(f)

                    job_id = data['job_id']
                    result = data['result']
                    success = data['success']
                    retry_count = data.get('retry_count')  # BUG-032: Load retryCount from queue
                    queued_at_raw = data.get('timestamp')

                    if queued_at_raw:
                        try:
                            queued_at = datetime.fromisoformat(str(queued_at_raw).replace('Z', '+00:00'))
                            if queued_at.tzinfo is not None:
                                queued_at = queued_at.replace(tzinfo=None)
                            age_hours = (datetime.now() - queued_at).total_seconds() / 3600
                            if age_hours > self.queue_result_max_age_hours:
                                os.remove(queue_file)
                                print(f"[Queue] Dropped stale queued result for job {job_id[:8]} ({age_hours:.1f}h old)")
                                continue
                        except Exception as age_err:
                            print(f"[Queue] Warning: could not parse queued timestamp for {job_id[:8]}: {age_err}")

                    print(f"[Queue] Resending result for job {job_id[:8]} with retryCount={retry_count}")
                    completion_sent = await self.complete_job(job_id, result, success, retry_count=retry_count)  # BUG-032

                    if completion_sent:
                        # Wait for ACK before deleting queue file
                        ack_received = await self.acknowledge_findings(job_id)

                        if ack_received:
                            os.remove(queue_file)
                            print(f"[Queue] ✓ Resent, ACK received, and removed queue file")
                        else:
                            print(f"[Queue] ⚠ Resend succeeded but ACK failed, keeping queue file for retry")
                    else:
                        if self._last_completion_status in (404, 409, 410):
                            os.remove(queue_file)
                            print(f"[Queue] Dropped terminal queued result for job {job_id[:8]} after HTTP {self._last_completion_status}")
                            continue
                        print(f"[Queue] ⚠ Resend failed, keeping queue file")

                except Exception as e:
                    print(f"[Queue] Error processing {queue_file}: {e}")

        except Exception as e:
            print(f"[Queue] Error: {e}")

    async def _periodic_template_update(self):
        """Periodically update nuclei templates every 24 hours"""
        import subprocess
        while True:
            try:
                await asyncio.sleep(86400)  # 24 hours
                print("[TemplateUpdate] Starting periodic nuclei template update...")
                process = await asyncio.create_subprocess_exec(
                    "nuclei", "-update-templates",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
                stdout_text = stdout.decode('utf-8', errors='replace') if stdout else ''
                template_lines = [l for l in stdout_text.split('\n') if 'templates' in l.lower()]
                if template_lines:
                    print(f"[TemplateUpdate] {template_lines[-1].strip()}")
                else:
                    print(f"[TemplateUpdate] Update completed (exit code: {process.returncode})")
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                print("[TemplateUpdate] Template update timed out after 5 minutes")
            except Exception as e:
                print(f"[TemplateUpdate] Error updating templates: {e}")

    async def stop(self):
        """Stop the agent"""
        print("\n[Agent] Stopping...")
        self.running = False
        # BUG-088: Clean up aiohttp session
        if self._session and not self._session.closed:
            await self._session.close()
            print("[Agent] HTTP session closed")
        print("[Agent] Stopped")

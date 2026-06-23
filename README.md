# ASM Platform Agent

The agent is responsible for executing security scanning tools and reporting results back to the platform.

## Features

- REST API polling for job acquisition (5-second interval)
- Plugin-based architecture for custom tools
- 62 scanning tools across 20+ tool categories
- Heartbeat monitoring with configurable interval
- Output streaming and progress tracking
- Reusable aiohttp session for efficient HTTP communication

The backend publishes job notifications through Pub/Sub, while the agent keeps its REST polling loop and heartbeats for execution.

## Setup (Docker -- Recommended)

The agent runs as part of the Docker Compose stack (5 agent containers by default):

```bash
docker-compose up -d
```

To restart all agents after code changes:

```bash
docker-compose restart agent agent2 agent3 agent4 agent5
```

Agent configuration for Docker lives in a single shared `config.docker.yaml` (template at `config.docker.yaml.example`) that all 5 containers mount. Per-instance identity (WP4) is established at boot: each container self-enrolls via `POST /agents/enroll/tenant` using the tenant installer creds (`AGENT_CLIENT_ID` / `AGENT_CLIENT_SECRET`) plus its own `AGENT_INSTALLATION_UID` (distinct per service in `docker-compose.yml`), and receives its OWN Agent row + API key — so each running instance has its own `currentLoad` counter and throughput scales with instance count. There is no static per-agent API key. The standalone (non-docker) workflow continues to use `config.yaml.example`.

Dark-web monitoring also supports Tor-routed onion sources through the internal `tor-proxy` service. See [docs/darkweb-onion-monitoring.md](../docs/darkweb-onion-monitoring.md) for the source catalog format and runtime knobs.

### Standalone Setup (Development Only)

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Create configuration file:
```bash
cp config.yaml.example config.yaml
```

3. Edit `config.yaml`:
   - Set your agent name and tags
   - Configure server URLs (use `http://localhost:3001/api` for local backend)
   - Add your API key (obtain from platform UI)
   - Enable/disable tools

4. Run:
```bash
python main_rest.py
```

## Creating Custom Tools

1. Create a new Python file in the `tools/` directory
2. Inherit from `ToolPlugin` base class
3. Implement required methods:
   - `name`: Unique tool identifier (format: "category:tool_name")
   - `description`: Tool description
   - `schema`: Parameter schema (JSON Schema format)
   - `execute`: Tool execution logic

Example:
```python
from plugin_interface import ToolPlugin

class MyCustomTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "custom:my_scanner"

    @property
    def description(self) -> str:
        return "My custom scanner tool"

    @property
    def schema(self):
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"}
            },
            "required": ["target"]
        }

    async def execute(self, parameters):
        target = parameters['target']
        # Your scanning logic here
        return {"result": "success"}
```

4. Add tool to `config.yaml` (standalone) or to the shared `config.docker.yaml` for Docker (all 5 agents pick it up automatically):
```yaml
tools:
  - name: "custom:my_scanner"
    enabled: true
```

5. Restart all agents:
```bash
docker-compose restart agent agent2 agent3 agent4 agent5
```

## Architecture

The agent uses a REST polling architecture:

1. Agent registers with the backend via `POST /api/agents/register`
2. Sends periodic heartbeats via `POST /api/agents/heartbeat`
3. Polls for pending jobs via `GET /api/agents/jobs/next`
4. Executes the assigned tool and streams output/progress updates
5. Reports job completion via `PATCH /api/jobs/:id`

Key files:

- `main_rest.py` -- Entry point
- `agent_core_rest.py` -- Core agent logic, REST polling, job execution
- `plugin_interface.py` -- Base class for all tool plugins
- `plugin_loader.py` -- Tool discovery and loading system
- `config.docker.yaml` -- Shared docker agent configuration (mounted into all 5 containers; per-instance identity via `AGENT_CLIENT_ID`/`AGENT_CLIENT_SECRET` + `AGENT_INSTALLATION_UID` self-enrollment)
- `config.docker.yaml.example` -- Template for the above
- `config.yaml.example` -- Standalone (non-docker) configuration template
- `tools/` -- All scanning tool implementations (62 tools)

## AI Login Tool (`agent/tools/browser_login_ai.py`)

Vendor-agnostic AI-driven browser login. Used by FULLY_AGENTIC `WEB_DAST` workflows whose target requires authentication. Supports both Anthropic (Claude with vision + tools) and Google Gemini (with `vision + json` mode).

### How a single login attempt works

1. Backend dispatches `agent.browser_login_ai` with parameters `loginUrl`, `username`, `password`, `loginInstructions`, optional `headless`, `timeoutSeconds`, `mfaAutoFillTimeout`, `mfaMaxRounds`.
2. Tool launches Chromium (`--no-sandbox` for ARM64; isolated `user_data_dir` is sprint backlog per BUG-585) and navigates to `loginUrl`.
3. Tool screenshots the page, extracts a sanitized form-HTML excerpt (`extract_form_elements`, capped at 12 KB), and calls the LLM routed to `agent.browser_login_ai`. Anthropic path uses tool-use; Gemini path uses `responseMimeType: "application/json"`.
4. LLM returns `{ usernameField: [...selectors...], passwordField: [...], submitButton: [...] }` — multi-strategy locators (CSS + XPath fallbacks).
5. Tool fills credentials via Playwright (NOT via the LLM — the LLM never sees credentials), submits, screenshots the post-submit page, and asks the LLM to classify (`success` / `mfa` / `error`).
6. On `success`: extract cookies, **filter to target domain or known session-cookie name prefixes** (BUG-556 fix), build `cookies_string`, emit `AUTH_LOGIN_RESULT { success: true, cookieCount }` to the trace.
7. On `mfa`: poll up to `mfaAutoFillTimeout` seconds for an auto-filled OTP field, click MFA submit, re-classify. Repeat up to `mfaMaxRounds` times.
8. On `error` or all retries exhausted: emit `AUTH_LOGIN_RESULT { success: false, error }`.

### Trace event flow

| Event kind | When |
|------------|------|
| `AUTH_LOGIN_REQUEST` | Tool dispatched, before browser launch |
| `AUTH_LOGIN_RESULT` | Tool returns success or failure |
| `SESSION_REUSED` | Pre-seeded session cookies from a prior run reused without re-login |
| `SESSION_INJECTED` | Cookies injected into a downstream scanner step (e.g., katana, nuclei) |

### Privacy / safety guarantees

- **Credentials never reach the LLM.** Only screenshots and sanitized form-HTML go to the LLM. Credentials are filled locally via Playwright after the LLM returns selectors.
- **Cookie domain + name allowlist.** `filter_login_cookies()` drops cookies whose domain is unrelated to the login URL AND whose name does not match a known session-cookie prefix (`PHPSESSID`, `JSESSIONID`, `ASPSESSIONID`, `auth*`, `csrf*`, etc.). Third-party tracker / analytics / SSO-intermediary cookies are not forwarded to the trace, downstream scanners, or artifact files. (BUG-556 fix.)
- **`storage_state` not forwarded.** Playwright's full localStorage + sessionStorage from every visited origin is intentionally dropped from the result. (BUG-558 fix.)
- **Gemini API key in header, not URL.** `x-goog-api-key` header is used; URL query strings are never. (BUG-557 fix.)
- **Error responses sanitized.** Any literal echo of the API key in upstream error bodies is `***REDACTED***` before raising the RuntimeError.

### Configuration

Routed via the LLM service binding `agent.browser_login_ai` in **Administration → LLM Providers → Routing**. Required capabilities: `text`, `vision`, `json`. Recommended models:

- Anthropic: `claude-sonnet-4-6` or `claude-opus-4-7`
- Google: `gemini-3.1-pro-preview` or `gemini-2.5-pro`

The agent uses the `/api/llm-relay/chat` backend endpoint when `RELAY_ONLY_LLM=true` (default), so individual agents do not need raw provider keys.

### Limitations and future work

- Captchas on login or MFA pages cause failure after timeout. Manual captcha solving is not supported.
- BUG-583 (defer): system prompt does not strongly defend against prompt-injection from page DOM. Hardening sprint will sanitize form HTML aggressively and add JSON schema validation on returned selector spec.
- BUG-584 (defer): MFA polling has no CAPTCHA fail-fast classification. Will burn budget for the full timeout window before failing.
- BUG-585 (defer): browser uses default profile directory; no per-run `user_data_dir` isolation. Sprint will add `tempfile.mkdtemp` + `shutil.rmtree`.
- BUG-588 (defer): no URL allowlist after navigation; browser can follow redirects to any domain. Sprint will pin to `urlparse(login_url).netloc`.

See `docs/user-guide.md` §6.5 for end-user setup and `docs/operator-guide.md` §3 for LLM provider configuration.

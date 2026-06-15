"""
Bounded curl request tool for agentic exploration.
"""

import json
import re
from typing import Any, Dict

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import redact_headers, run_process


def _is_readonly_graphql_post(parameters: Dict[str, Any]) -> bool:
    """Return True when a POST is a read-only GraphQL query/introspection.

    GraphQL queries are conventionally issued over POST but are read-only by
    GraphQL semantics — only ``mutation``/``subscription`` operations change
    state. We allow such read-only API spot-checks without the
    ``allowUnsafeMethods`` flag (which stays required for PUT/PATCH/DELETE and
    for non-GraphQL POST bodies). A body whose GraphQL operation begins with
    ``mutation`` or ``subscription`` is still treated as unsafe.
    """
    body = parameters.get("body")
    if not isinstance(body, str) or not body.strip():
        return False
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError):
        return False
    query = parsed.get("query") if isinstance(parsed, dict) else None
    if not isinstance(query, str) or "{" not in query:
        return False
    # Reject if the first GraphQL operation keyword is a write operation.
    first_op = re.match(r"\s*(query|mutation|subscription)\b", query, re.IGNORECASE)
    if first_op and first_op.group(1).lower() in {"mutation", "subscription"}:
        return False
    # Also reject anonymous bodies that contain a mutation/subscription block.
    if re.search(r"\b(mutation|subscription)\b", query, re.IGNORECASE):
        return False
    return True


class CurlRequestTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "curl:request"

    @property
    def description(self) -> str:
        return "Runs a bounded curl request for safe evidence collection and API spot checks. Defaults to GET/HEAD/OPTIONS; read-only GraphQL query/introspection POSTs (JSON body with a non-mutation \"query\") are allowed automatically; other unsafe methods (PUT/PATCH/DELETE or non-GraphQL POST) require allowUnsafeMethods=true."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "target": {"type": "string"},
                "method": {"type": "string", "default": "GET"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
                "timeoutSeconds": {"type": "integer", "default": 20},
                "followRedirects": {"type": "boolean", "default": True},
                "maxBytes": {"type": "integer", "default": 200000},
                "includeHeaders": {"type": "boolean", "default": True},
                "allowUnsafeMethods": {"type": "boolean", "default": False},
                "cookie": {"type": "string"},
                "authCookies": {"type": "string"},
            },
            "oneOf": [{"required": ["url"]}, {"required": ["target"]}],
        }

    @property
    def metadata(self):
        return {
            "category": "agentic-recon",
            "phase": 2,
            "domain": ["web", "api"],
            "input_type": ["url"],
            "output_type": ["http_response"],
            "chainable_after": ["api:", "param:", "decision:", "js:"],
            "chainable_before": ["decision:", "nuclei:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        url = parameters.get("url") or parameters.get("target")
        if not url:
            return {"success": False, "error": "url or target is required"}
        method = str(parameters.get("method") or "GET").upper()
        if method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}:
            return {"success": False, "error": f"unsupported method: {method}"}
        if (
            method not in {"GET", "HEAD", "OPTIONS"}
            and not bool(parameters.get("allowUnsafeMethods", False))
            and not (method == "POST" and _is_readonly_graphql_post(parameters))
        ):
            return {
                "success": False,
                "error": f"method {method} requires allowUnsafeMethods=true",
                "safeMethods": ["GET", "HEAD", "OPTIONS"],
                "hint": "Read-only GraphQL query/introspection POSTs (JSON body with a non-mutation \"query\") are allowed without allowUnsafeMethods.",
            }

        timeout_seconds = max(3, min(int(parameters.get("timeoutSeconds") or 20), 120))
        max_bytes = max(10_000, min(int(parameters.get("maxBytes") or 200_000), 2_000_000))
        include_headers = bool(parameters.get("includeHeaders", True))
        follow_redirects = bool(parameters.get("followRedirects", True))

        cmd = [
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            str(timeout_seconds),
            "--connect-timeout",
            "8",
            "--request",
            method,
            "--output",
            "-",
            "--write-out",
            "\n__XASM_CURL_META__%{http_code} %{url_effective} %{time_total} %{size_download}\n",
        ]
        if include_headers:
            cmd.append("--include")
        if follow_redirects:
            cmd.append("--location")

        headers = parameters.get("headers") if isinstance(parameters.get("headers"), dict) else {}
        cookie = parameters.get("cookie") or parameters.get("authCookies")
        if cookie:
            headers = {**headers, "Cookie": str(cookie)}
        for key, value in headers.items():
            cmd.extend(["--header", f"{key}: {value}"])
        body = parameters.get("body")
        if body is not None:
            cmd.extend(["--data-raw", str(body)])
        cmd.append(str(url))

        output = await run_process(cmd, timeout=timeout_seconds + 5)
        stdout = output.get("stdout") or ""
        meta = {}
        if "__XASM_CURL_META__" in stdout:
            body_text, meta_line = stdout.rsplit("__XASM_CURL_META__", 1)
            parts = meta_line.strip().split(" ", 3)
            if len(parts) >= 4:
                meta = {
                    "status": int(parts[0]) if parts[0].isdigit() else None,
                    "effectiveUrl": parts[1],
                    "timeTotal": float(parts[2]) if parts[2].replace(".", "", 1).isdigit() else None,
                    "downloadBytes": int(float(parts[3])) if parts[3].replace(".", "", 1).isdigit() else None,
                }
            stdout = body_text

        truncated = len(stdout) > max_bytes
        if truncated:
            stdout = stdout[:max_bytes]

        return {
            "success": output.get("returnCode") == 0,
            "url": url,
            "method": method,
            "meta": meta,
            "requestHeaders": redact_headers(headers),
            "responseSample": stdout,
            "stderr": (output.get("stderr") or "")[:4000],
            "returnCode": output.get("returnCode"),
            "timedOut": output.get("timedOut"),
            "truncated": truncated,
            "summary": {
                "status": meta.get("status"),
                "effectiveUrl": meta.get("effectiveUrl"),
                "bytesReturned": len(stdout),
                "truncated": truncated,
            },
        }


def get_tool():
    return CurlRequestTool()


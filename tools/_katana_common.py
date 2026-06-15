"""
Shared helpers for Katana-based crawler tools.
"""

import os
from typing import Any, Dict, List


KATANA_ADVANCED_SCHEMA: Dict[str, Any] = {
    "authCookies": {
        "type": "string",
        "description": "Session cookies injected by authentication steps",
    },
    "authHeadersFile": {
        "type": "string",
        "description": "Headers file injected by authentication steps",
    },
    "headless": {
        "type": "boolean",
        "description": "Enable Katana headless hybrid crawling",
        "default": False,
    },
    "jsCrawl": {
        "type": "boolean",
        "description": "Parse and crawl JavaScript endpoints",
        "default": True,
    },
    "jsluice": {
        "type": "boolean",
        "description": "Enable jsluice parsing for JavaScript files (memory intensive)",
        "default": False,
    },
    "xhrExtraction": {
        "type": "boolean",
        "description": "Extract XHR request URLs and methods from headless crawling",
        "default": False,
    },
    "formExtraction": {
        "type": "boolean",
        "description": "Extract forms, inputs, textarea, and select elements in JSONL output",
        "default": True,
    },
    "automaticFormFill": {
        "type": "boolean",
        "description": "Enable Katana automatic form filling / automatic login support",
        "default": False,
    },
    "knownFiles": {
        "type": "string",
        "description": "Known files to crawl (all, robotstxt, sitemapxml, or empty to disable)",
        "default": "all",
    },
    "pageLoadStrategy": {
        "type": "string",
        "description": "Optional Chrome page load strategy for headless crawling",
    },
    "maxResponseSize": {
        "type": "integer",
        "description": "Maximum response size Katana should read",
        "default": 2097152,
    },
    "concurrency": {
        "type": "integer",
        "description": "Katana fetcher concurrency",
        "default": 10,
    },
    "parallelism": {
        "type": "integer",
        "description": "Katana input parallelism",
        "default": 5,
    },
    "requestTimeout": {
        "type": "integer",
        "description": "Per-request timeout in seconds",
        "default": 10,
    },
    "retry": {
        "type": "integer",
        "description": "Number of request retries",
        "default": 1,
    },
}


def extend_katana_schema(properties: Dict[str, Any]) -> Dict[str, Any]:
    """Add common Katana v1.6 crawl controls to a schema properties object."""
    return {**properties, **KATANA_ADVANCED_SCHEMA}


def get_auth_cookie(parameters: Dict[str, Any]) -> str:
    """Resolve explicit or workflow-injected cookies."""
    return parameters.get("cookie") or parameters.get("authCookies") or ""


def get_headers_file(parameters: Dict[str, Any]) -> str:
    """Resolve explicit or workflow-injected headers file."""
    return parameters.get("headers_file") or parameters.get("authHeadersFile") or ""


def add_katana_options(
    cmd: List[str],
    parameters: Dict[str, Any],
    rate_limit_config: Dict[str, Any] | None = None,
) -> List[str]:
    """Append modern Katana crawl/auth/rate-limit options to a command."""
    headless_enabled = (
        parameters.get("headless", False)
        or parameters.get("automaticFormFill", False)
        or parameters.get("xhrExtraction", False)
        or bool(parameters.get("pageLoadStrategy"))
    )
    if headless_enabled:
        cmd.extend(["-hl", "-nos"])

    if parameters.get("jsCrawl", True):
        cmd.append("-jc")

    if parameters.get("jsluice", False):
        cmd.append("-jsl")

    if parameters.get("xhrExtraction", False):
        cmd.append("-xhr")

    if parameters.get("formExtraction", True):
        cmd.append("-fx")

    if parameters.get("automaticFormFill", False):
        cmd.append("-aff")

    known_files = parameters.get("knownFiles", "all")
    if known_files:
        cmd.extend(["-kf", str(known_files)])

    page_load_strategy = parameters.get("pageLoadStrategy")
    if page_load_strategy:
        cmd.extend(["-pls", str(page_load_strategy)])

    max_response_size = parameters.get("maxResponseSize")
    if max_response_size:
        cmd.extend(["-mrs", str(max_response_size)])

    request_timeout = parameters.get("requestTimeout")
    if request_timeout:
        cmd.extend(["-timeout", str(request_timeout)])

    retry = parameters.get("retry")
    if retry is not None:
        cmd.extend(["-retry", str(retry)])

    concurrency = parameters.get("concurrency") or (rate_limit_config or {}).get("concurrency")
    if concurrency:
        cmd.extend(["-c", str(concurrency)])

    parallelism = parameters.get("parallelism")
    if parallelism:
        cmd.extend(["-p", str(parallelism)])

    if rate_limit_config and rate_limit_config.get("rateLimit"):
        cmd.extend(["-rl", str(rate_limit_config["rateLimit"])])
    elif parameters.get("rateLimit"):
        cmd.extend(["-rl", str(parameters["rateLimit"])])

    headers_file = get_headers_file(parameters)
    cookie = get_auth_cookie(parameters)
    if headers_file and os.path.exists(headers_file):
        cmd.extend(["-H", f"@{headers_file}"])
    elif cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])

    return cmd

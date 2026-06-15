"""
Shared scope exclusion and rate limiting utilities for agent tools.
"""

import re


def extract_exclusion_patterns(parameters: dict) -> list:
    """Extract URL exclusion patterns from parameters.
    Checks parameters.exclusionPatterns.urlPatterns and parameters.exclusionRules.urlPatterns.
    Returns a list of URL pattern strings.
    """
    exclusion_patterns = parameters.get("exclusionPatterns") or parameters.get("exclusionRules")
    if exclusion_patterns and isinstance(exclusion_patterns, dict):
        return exclusion_patterns.get("urlPatterns", [])
    return []


def extract_rate_limit(parameters: dict) -> dict:
    """Extract rate limit settings from parameters.
    Checks parameters.scopeControls.rateLimit and parameters.rateLimit.
    Returns dict with 'rateLimit' (requests/sec) and 'concurrency' keys, or empty dict.
    """
    scope_controls = parameters.get("scopeControls")
    if scope_controls and isinstance(scope_controls, dict):
        rl = scope_controls.get("rateLimit")
        if rl is not None:
            return {"rateLimit": int(rl), "concurrency": int(scope_controls.get("concurrency", 10))}

    rl = parameters.get("rateLimit")
    if rl is not None:
        return {"rateLimit": int(rl), "concurrency": int(parameters.get("concurrency", 10))}

    return {}


def extract_auth_cookie(parameters: dict) -> str:
    """Return explicit or workflow-injected session cookies."""
    return parameters.get("cookie") or parameters.get("authCookies") or ""


def extract_auth_headers_file(parameters: dict) -> str:
    """Return explicit or workflow-injected auth headers file."""
    return parameters.get("headers_file") or parameters.get("authHeadersFile") or ""


def filter_excluded_urls(urls: list, exclusion_url_patterns: list, log_prefix: str = "") -> list:
    """Filter URLs against exclusion patterns. Returns filtered list.
    Each pattern is treated as a regex match against the full URL.
    """
    if not exclusion_url_patterns or not urls:
        return urls

    compiled = []
    for pattern in exclusion_url_patterns:
        try:
            compiled.append(re.compile(pattern))
        except re.error:
            # Treat as literal substring match if not a valid regex
            compiled.append(re.compile(re.escape(pattern)))

    filtered = []
    excluded_count = 0
    for url in urls:
        excluded = False
        for regex in compiled:
            if regex.search(url):
                excluded = True
                excluded_count += 1
                break
        if not excluded:
            filtered.append(url)

    if excluded_count > 0 and log_prefix:
        print(f"[{log_prefix}] Excluded {excluded_count} URLs matching exclusion patterns")

    return filtered

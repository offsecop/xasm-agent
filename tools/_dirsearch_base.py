"""
Shared Dirsearch utility functions used by all 3 dirsearch tool files.
Extracted to fix BUG-248 (code duplication).
"""

import hashlib
import json
import os
import re
import urllib.request
from urllib.parse import urlparse, unquote


# Dirsearch official dicc.txt wordlist URL
DICC_WORDLIST_URL = "https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt"
DICC_WORDLIST_PATH = "/tmp/dirsearch_dicc.txt"
COMBINED_WORDLIST_DIR = "/tmp/xasm_dirsearch_wordlists"

# The agent is mounted at /app in Docker, so /app/wordlists/fuzz.txt is the
# durable runtime location for customer-provided additions.
COMMON_WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirsearch/db/dicc.txt",
]
FUZZ_WORDLIST_CANDIDATES = [
    "/app/wordlists/fuzz.txt",
    "/app/fuzz.txt",
    "/workspace/fuzz.txt",
    "/usr/share/wordlists/xasm/fuzz.txt",
    os.path.join(os.getcwd(), "wordlists", "fuzz.txt"),
    os.path.join(os.getcwd(), "fuzz.txt"),
]


def ensure_dicc_wordlist(tool_label: str = "Dirsearch") -> str:
    """Download dicc.txt wordlist if not present."""
    if os.path.exists(DICC_WORDLIST_PATH):
        size = os.path.getsize(DICC_WORDLIST_PATH)
        if size > 100000:  # > 100KB indicates valid wordlist
            return DICC_WORDLIST_PATH

    try:
        print(f"[{tool_label}] Downloading dicc.txt wordlist from {DICC_WORDLIST_URL}")
        urllib.request.urlretrieve(DICC_WORDLIST_URL, DICC_WORDLIST_PATH)
        size = os.path.getsize(DICC_WORDLIST_PATH)
        print(f"[{tool_label}] Downloaded dicc.txt ({size} bytes)")
        return DICC_WORDLIST_PATH
    except Exception as e:
        print(f"[{tool_label}] Failed to download dicc.txt: {e}")
        return None


def _is_enabled(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def _coerce_wordlist_paths(value):
    if not value:
        return []
    if isinstance(value, list):
        values = value
    elif isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        try:
            parsed = json.loads(stripped)
            values = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            values = re.split(r"[\n,]", stripped)
    else:
        values = [value]

    paths = []
    for item in values:
        path = str(item).strip()
        if path:
            paths.append(path)
    return paths


def _existing_wordlists(paths):
    existing = []
    seen = set()
    for path in paths:
        if not path:
            continue
        expanded = os.path.abspath(os.path.expanduser(str(path)))
        if expanded in seen:
            continue
        if os.path.exists(expanded) and os.path.isfile(expanded):
            seen.add(expanded)
            existing.append(expanded)
    return existing


def discover_extra_wordlists(parameters=None):
    """Resolve optional customer wordlists that should augment dirsearch defaults."""
    parameters = parameters or {}
    explicit_paths = []
    for key in (
        "extraWordlist",
        "extraWordlists",
        "additionalWordlist",
        "additionalWordlists",
        "fuzzWordlist",
    ):
        explicit_paths.extend(_coerce_wordlist_paths(parameters.get(key)))

    env_paths = []
    env_paths.extend(_coerce_wordlist_paths(os.environ.get("DIRSEARCH_EXTRA_WORDLISTS")))
    env_paths.extend(_coerce_wordlist_paths(os.environ.get("DIRSEARCH_FUZZ_WORDLIST")))

    auto_paths = []
    if _is_enabled(parameters.get("includeFuzzWordlist"), default=True):
        auto_paths.extend(FUZZ_WORDLIST_CANDIDATES)

    return _existing_wordlists(explicit_paths + env_paths + auto_paths)


def _first_common_wordlist():
    existing = _existing_wordlists(COMMON_WORDLIST_CANDIDATES)
    return existing[0] if existing else None


def _combined_wordlist_path(wordlists):
    digest = hashlib.sha256()
    for path in wordlists:
        stat = os.stat(path)
        digest.update(path.encode("utf-8"))
        digest.update(str(stat.st_size).encode("utf-8"))
        digest.update(str(int(stat.st_mtime)).encode("utf-8"))
    return os.path.join(COMBINED_WORDLIST_DIR, f"dirsearch-{digest.hexdigest()[:16]}.txt")


def combine_wordlists(wordlists, tool_label="Dirsearch"):
    """Merge wordlists into a deduplicated temp file, preserving first-seen order."""
    valid_wordlists = _existing_wordlists(wordlists)
    if not valid_wordlists:
        return None
    if len(valid_wordlists) == 1:
        return valid_wordlists[0]

    os.makedirs(COMBINED_WORDLIST_DIR, exist_ok=True)
    output_path = _combined_wordlist_path(valid_wordlists)
    if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
        return output_path

    seen = set()
    total_written = 0
    with open(output_path, "w", encoding="utf-8") as output:
        for wordlist in valid_wordlists:
            with open(wordlist, "r", encoding="utf-8", errors="ignore") as handle:
                for raw_line in handle:
                    entry = raw_line.strip()
                    if not entry or entry in seen:
                        continue
                    seen.add(entry)
                    output.write(f"{entry}\n")
                    total_written += 1

    print(
        f"[{tool_label}] Built combined wordlist with {total_written} unique entries "
        f"from {len(valid_wordlists)} files: {output_path}"
    )
    return output_path


def resolve_dirsearch_wordlist(
    default_wordlist=None,
    parameters=None,
    tool_label="Dirsearch",
    prefer_common_wordlist=False,
):
    """Return the effective dirsearch wordlist plus metadata for logging.

    If a fuzz/additional wordlist exists, it is appended to the tool's normal
    base wordlist. If no extra list exists, the caller's original behavior is
    preserved.
    """
    parameters = parameters or {}
    extra_wordlists = discover_extra_wordlists(parameters)
    base_wordlist = default_wordlist if default_wordlist and os.path.exists(default_wordlist) else None

    if prefer_common_wordlist and extra_wordlists and not base_wordlist:
        base_wordlist = _first_common_wordlist()

    if base_wordlist:
        base_abs = os.path.abspath(base_wordlist)
        extra_wordlists = [
            path for path in extra_wordlists if os.path.abspath(path) != base_abs
        ]

    wordlists = []
    if base_wordlist:
        wordlists.append(base_wordlist)
    wordlists.extend(extra_wordlists)

    effective_wordlist = combine_wordlists(wordlists, tool_label=tool_label)
    return effective_wordlist, {
        "base_wordlist": base_wordlist,
        "extra_wordlists": extra_wordlists,
        "combined": bool(effective_wordlist and len(wordlists) > 1),
    }


def describe_wordlist_selection(info):
    base = info.get("base_wordlist")
    extras = info.get("extra_wordlists") or []
    if base and extras:
        return f"base {os.path.basename(base)} + {len(extras)} extra wordlist(s)"
    if extras:
        return f"{len(extras)} extra wordlist(s)"
    if base:
        return os.path.basename(base)
    return "dirsearch built-in wordlist"


def filter_results(endpoints):
    """Filter false positives from dirsearch results.

    Removes:
    1. Path traversal URLs (../  %2e%2e  %252e  %c0%ae  etc.)
    2. Catch-all responses (>50% of results share same status+size signature)
    """
    if not endpoints:
        return endpoints, {'filtered_count': 0, 'filter_reasons': {}}

    filter_reasons = {}
    traversal_re = re.compile(r'(\.\.|%2e|%252e|%c0%ae|%c1%9c)', re.IGNORECASE)

    # Detect catch-all: if >50% of results share the same (status, content_length), flag it
    signature_counts = {}
    for ep in endpoints:
        sig = (ep.get('status_code'), ep.get('content_length'))
        signature_counts[sig] = signature_counts.get(sig, 0) + 1

    total = len(endpoints)
    catchall_signatures = set()
    for sig, count in signature_counts.items():
        if count > 1 and count > total * 0.5:
            catchall_signatures.add(sig)

    filtered = []
    for ep in endpoints:
        url = ep.get('url', '')
        parsed_path = urlparse(url).path
        decoded_path = unquote(unquote(parsed_path))

        # Filter path traversal payloads
        if traversal_re.search(url) or '..' in decoded_path:
            filter_reasons['path_traversal'] = filter_reasons.get('path_traversal', 0) + 1
            continue

        # Filter catch-all responses
        sig = (ep.get('status_code'), ep.get('content_length'))
        if sig in catchall_signatures:
            filter_reasons['catch_all_response'] = filter_reasons.get('catch_all_response', 0) + 1
            continue

        filtered.append(ep)

    filtered_count = total - len(filtered)
    return filtered, {'filtered_count': filtered_count, 'filter_reasons': filter_reasons}

"""
Shared Dirsearch utility functions used by all 3 dirsearch tool files.
Extracted to fix BUG-248 (code duplication).
"""

import os
import re
import urllib.request
from urllib.parse import urlparse, unquote


# Dirsearch official dicc.txt wordlist URL
DICC_WORDLIST_URL = "https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt"
DICC_WORDLIST_PATH = "/tmp/dirsearch_dicc.txt"


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

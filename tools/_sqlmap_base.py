"""
Shared SQLMap utility functions used by all 6 sqlmap tool files.
Extracted to fix BUG-247 (code duplication) and BUG-244 (IP target rejection).
"""

import os
import re
from urllib.parse import urlparse


def is_valid_target(target: str) -> bool:
    """Validate that a target looks like a legitimate URL or hostname.

    Fixes BUG-244: Now accepts bare IP addresses like 192.168.1.1.
    """
    if not target or len(target) < 3:
        return False

    # Reject common filename artifacts
    invalid_names = ['log', 'test', 'output', 'tmp', 'scan', 'result', 'data', 'dump']
    if target.lower() in invalid_names:
        return False

    # Must start with http:// or https:// OR look like a hostname/IP
    if target.startswith('http://') or target.startswith('https://'):
        return True

    # Check if it looks like a hostname or IP address
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
    if re.match(hostname_pattern, target):
        # Accept if it contains letters (hostname) OR looks like an IP address
        if any(c.isalpha() for c in target):
            return True
        # BUG-244 fix: Accept IP addresses (digits and dots only, valid octets)
        ip_pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
        if re.match(ip_pattern, target):
            return True

    return False


def build_target_map(targets: list) -> dict:
    """Build a mapping from hostname to full target URL for log matching."""
    target_map = {}
    if targets:
        for target in targets:
            try:
                parsed = urlparse(target if target.startswith('http') else f'http://{target}')
                hostname = parsed.hostname or parsed.netloc.split(':')[0]
                target_map[hostname] = target
            except Exception:
                pass
    return target_map


def parse_sqlmap_logs(output_dir: str, targets: list = None, tool_label: str = "SQLMap") -> list:
    """Parse SQLMap log files for structured vulnerability data.

    Args:
        output_dir: Directory containing SQLMap logs
        targets: List of target URLs scanned (for fallback if log parsing fails)
        tool_label: Label for log messages (e.g., "SQLMap Quick", "SQLMap Full")
    """
    vulnerabilities = []

    try:
        if not os.path.exists(output_dir):
            print(f"[{tool_label}] Output directory not found: {output_dir}")
            return vulnerabilities

        target_map = build_target_map(targets)

        for root, dirs, files in os.walk(output_dir):
            for file in files:
                if file.endswith('.log') or file == 'log':
                    log_path = os.path.join(root, file)

                    # Try to find matching target from directory structure
                    fallback_target = None
                    if target_map:
                        for hostname, target_url in target_map.items():
                            if hostname in root:
                                fallback_target = target_url
                                break

                    vuln = parse_log_file(log_path, fallback_target, tool_label)
                    if vuln:
                        vulnerabilities.append(vuln)
    except Exception as e:
        print(f"[{tool_label}] Error parsing logs: {e}")

    return vulnerabilities


def extract_target_url(content: str, log_path: str, fallback_target: str = None, tool_label: str = "SQLMap") -> str:
    """Extract the target URL from SQLMap log content using multiple methods.

    Returns the extracted URL or None if not found.
    """
    target_url = None

    # Method 1: Look for "Target URL:" in log
    for line in content.split('\n'):
        if line.startswith('[') and 'Target URL:' in line:
            parts = line.split('Target URL:', 1)
            if len(parts) == 2:
                target_url = parts[1].strip()
                break

    # Method 2: Look for "testing URL"
    if not target_url:
        for line in content.split('\n'):
            if 'testing connection to the target url' in line.lower():
                continue
            elif 'testing' in line.lower() and 'url' in line.lower():
                if "'" in line:
                    parts = line.split("'")
                    if len(parts) >= 2:
                        potential_url = parts[1]
                        if potential_url.startswith('http'):
                            target_url = potential_url
                            break

    # Method 3: Use fallback if provided
    if not target_url and fallback_target:
        target_url = fallback_target
        print(f"[{tool_label}] Using fallback target (actual scanned URL): {target_url}")

    # Method 4: Extract from directory structure
    if not target_url:
        dir_path = os.path.dirname(log_path)
        parent_dir = os.path.basename(dir_path)
        if parent_dir and is_valid_target(parent_dir):
            target_url = parent_dir
            print(f"[{tool_label}] Extracted target from directory: {target_url}")

    # Method 5: Try filename as last resort
    if not target_url:
        filename_target = os.path.basename(log_path).replace(".log", "")
        if is_valid_target(filename_target):
            target_url = filename_target
            print(f"[{tool_label}] Using validated filename as target: {target_url}")
        else:
            print(f"[{tool_label}] ERROR: Could not extract valid target from {log_path}, filename '{filename_target}' is invalid")

    return target_url


def parse_log_file(log_path: str, fallback_target: str = None, tool_label: str = "SQLMap") -> dict:
    """Extract vulnerability details from a SQLMap log file.

    This is the base parser that extracts common fields. Individual tools may
    extend the returned dict with additional fields.
    """
    try:
        with open(log_path, 'r', errors='replace') as f:
            content = f.read()

        if "sqlmap identified" not in content.lower() and "injectable" not in content.lower():
            return None

        target_url = extract_target_url(content, log_path, fallback_target, tool_label)
        if not target_url:
            return None

        vuln = {
            "target": target_url,
            "vulnerable": True,
            "injection_type": None,
            "parameter": None,
            "dbms": None,
            "payloads": []
        }

        lines = content.split('\n')
        for i, line in enumerate(lines):
            # Parameter detection: "Parameter: id (GET)"
            if line.startswith("Parameter:"):
                parts = line.split(":")
                if len(parts) >= 2:
                    param_info = parts[1].strip()
                    vuln["parameter"] = param_info.split("(")[0].strip()

            # Injection type: "    Type: boolean-based blind"
            if line.strip().startswith("Type:") and not vuln["injection_type"]:
                injection_type = line.split(":", 1)[1].strip()
                vuln["injection_type"] = injection_type

            # Old format: "parameter 'id' appears to be ... injectable"
            if "parameter" in line.lower() and "appears to be" in line.lower():
                if "'" in line:
                    parts = line.split("'")
                    if len(parts) >= 2 and not vuln["parameter"]:
                        vuln["parameter"] = parts[1]
                    if len(parts) >= 4 and not vuln["injection_type"]:
                        vuln["injection_type"] = parts[3]

            # DBMS
            if "back-end DBMS" in line.lower():
                if ":" in line:
                    vuln["dbms"] = line.split(":", 1)[1].strip()

            # Payloads
            if "Payload:" in line:
                if i + 1 < len(lines):
                    payload = lines[i + 1].strip()
                    if payload and payload not in vuln["payloads"]:
                        vuln["payloads"].append(payload)

            # Title (fallback for injection_type)
            if "Title:" in line:
                if i + 1 < len(lines):
                    title = lines[i + 1].strip()
                    if not vuln["injection_type"] and title:
                        vuln["injection_type"] = title

        return vuln if vuln["vulnerable"] else None

    except Exception as e:
        print(f"[{tool_label}] Error parsing log file {log_path}: {e}")
        return None

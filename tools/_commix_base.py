"""
Shared Commix utility functions used by both commix tool files.
Extracted to fix BUG-249 (code duplication).
"""

import re


def parse_commix_output(raw_output: str, target_url: str) -> list:
    """Parse Commix stdout for vulnerability findings.

    Commix output patterns:
      [+] The parameter 'X' is vulnerable to results-based command injection
      [+] Type: Results-based (technique: classic)
      [+] Payload: ;echo RANDOMSTRING
      [*] Testing parameter 'X'
    """
    findings = []
    lines = raw_output.split('\n')

    current_parameter = None
    current_technique = None
    current_injection_type = None
    current_payload = None

    for line in lines:
        stripped = line.strip()

        # Track which parameter is being tested
        param_match = re.search(r"Testing parameter ['\"](\w+)['\"]", stripped)
        if param_match:
            current_parameter = param_match.group(1)

        # Detect vulnerability confirmation
        vuln_match = re.search(
            r"\[\+\]\s+The (?:GET|POST|Cookie|Header)?\s*parameter ['\"](\w+)['\"].*?is vulnerable.*?(results-based|time-based|file-based|blind)?\s*command injection",
            stripped, re.IGNORECASE
        )
        if vuln_match:
            current_parameter = vuln_match.group(1)
            current_injection_type = vuln_match.group(2) or "unknown"

        # Detect injection type/technique
        type_match = re.search(r"\[\+\]\s+Type:\s*(.+?)(?:\(technique:\s*(.+?)\))?$", stripped)
        if type_match:
            current_injection_type = type_match.group(1).strip()
            if type_match.group(2):
                current_technique = type_match.group(2).strip()

        # Detect payload
        payload_match = re.search(r"\[\+\]\s+Payload:\s*(.+)$", stripped)
        if payload_match:
            current_payload = payload_match.group(1).strip()

            # We have enough info to create a finding
            if current_parameter:
                technique_label = current_technique or "unknown"
                injection_label = current_injection_type or "command injection"

                finding = {
                    "parameter": current_parameter,
                    "url": target_url,
                    "technique": technique_label,
                    "injection_type": injection_label,
                    "payload": current_payload,
                    "severity": "CRITICAL",
                    "title": f"OS Command Injection: {technique_label} in '{current_parameter}'",
                    "evidence": f"Commix confirmed {injection_label} (technique: {technique_label}) in parameter '{current_parameter}' with payload: {current_payload}"
                }
                findings.append(finding)

                # Reset for next finding
                current_payload = None
                current_technique = None
                current_injection_type = None

        # Also detect successful exploitation markers
        exploit_match = re.search(
            r"\[\+\].*parameter ['\"](\w+)['\"].*appears to be injectable",
            stripped, re.IGNORECASE
        )
        if exploit_match and not any(f["parameter"] == exploit_match.group(1) for f in findings):
            param = exploit_match.group(1)
            finding = {
                "parameter": param,
                "url": target_url,
                "technique": "unknown",
                "injection_type": "command injection",
                "payload": "",
                "severity": "CRITICAL",
                "title": f"OS Command Injection in '{param}'",
                "evidence": f"Commix detected command injection in parameter '{param}'"
            }
            findings.append(finding)

    return findings

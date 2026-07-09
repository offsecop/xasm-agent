"""
Plugin interface definition for custom tools
All custom tools must inherit from this base class
"""

from abc import ABC, abstractmethod
from typing import Dict, Any

class ToolPlugin(ABC):
    """
    Base class for all tool plugins
    
    Custom tools should inherit from this class and implement
    the required methods.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """
        Return the unique name of the tool
        Format: "category:tool_name"
        Example: "nmap:port_scan", "custom:my_scanner"
        """
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Return a description of what this tool does"""
        pass
    
    @property
    def schema(self) -> Dict[str, Any]:
        """
        Return the JSON schema for tool parameters
        Override this to define expected parameters
        """
        return {
            "type": "object",
            "properties": {},
            "required": []
        }
    
    @abstractmethod
    async def execute(self, parameters: Dict[str, Any]) -> Any:
        """
        Execute the tool with given parameters
        
        Args:
            parameters: Dictionary of parameters as defined in schema
            
        Returns:
            Tool output (will be sent back to platform)
        """
        pass
    
    @property
    def metadata(self) -> Dict[str, Any]:
        """
        Tool taxonomy metadata for workflow orchestration.

        Override to return a dict with:
          category: str - recon, discovery, enumeration, vuln-scan, exploit-test, enrichment, auth, screenshot
          phase: int - 0-5 execution order in a typical pipeline
          domain: list[str] - web, infra, dns, ssl, osint
          input_type: list[str] - ip, hostname, domain, url, url_with_params, fqdn, query
          output_type: list[str] - ips, hostnames, domains, urls, urls_with_params, ports, services, findings, screenshots, session
          chainable_after: list[str] - recommended predecessor tool prefixes
          chainable_before: list[str] - recommended successor tool prefixes

        Canonical taxonomy (#559) — ADDITIVE; the legacy keys above are kept for
        back-compat. These are OPTIONAL: tools that omit them get the fields
        backfilled from the legacy triple by tools/_taxonomy.py:derive_canonical().
        Declare them explicitly for multi-purpose tools so each mode is enumerated.
          taxonomy_domain: list[str] - canonical domains (web, infra, api, osint,
                           dns, brand-drp, code, meta); first = primary
          lifecycle_phase: str - canonical phase (recon-passive, recon-active,
                           discovery, assessment, scan, exploit-test, post-exploit,
                           enrichment, auth, reporting, orchestration)
          purpose_count: str - "single" | "multi"
          primary_purpose: str - one-line human capability summary
          secondary_purposes: list[{mode, purpose}] - multi-purpose tools only
          alias_of: str - (optional) another tool name this one aliases
        """
        return {}

    def validate_parameters(self, parameters: Dict[str, Any]) -> bool:
        """
        Validate parameters against schema.
        Checks required fields and basic type constraints.
        """
        schema = self.schema
        if not schema or schema.get("type") != "object":
            return True

        properties = schema.get("properties", {})
        required = schema.get("required", [])

        # Check all required fields are present
        for field in required:
            if field not in parameters:
                print(f"[Validate] Missing required parameter '{field}' for {self.name}")
                return False

        # Basic type checking for provided parameters
        type_map = {
            "string": str,
            "integer": int,
            "boolean": bool,
            "array": list,
            "object": dict,
        }

        for field, value in parameters.items():
            if field.startswith("_"):
                continue  # Skip internal parameters
            if field not in properties:
                continue  # Allow extra parameters
            expected_type = properties[field].get("type")
            if expected_type and expected_type in type_map:
                py_type = type_map[expected_type]
                if not isinstance(value, py_type):
                    # Allow float for integer fields
                    if expected_type == "integer" and isinstance(value, float):
                        continue
                    # Coerce string to integer if the value is a valid integer string
                    if expected_type == "integer" and isinstance(value, str):
                        try:
                            int(value)
                            continue
                        except ValueError:
                            pass
                    # Coerce string to boolean if it's a recognized boolean string
                    if expected_type == "boolean" and isinstance(value, str):
                        if value.lower() in ("true", "false", "1", "0"):
                            continue
                    print(f"[Validate] Parameter '{field}' expected {expected_type}, got {type(value).__name__} for {self.name}")
                    return False

        return True


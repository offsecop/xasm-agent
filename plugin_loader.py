"""
Plugin loader for custom tools
Handles loading and managing tool plugins
"""

import importlib
import importlib.util
import inspect
from pathlib import Path
from typing import Dict, Any
from plugin_interface import ToolPlugin

class PluginLoader:
    def __init__(self, config, agent=None):
        self.config = config
        self.agent = agent  # Reference to agent for progress reporting
        self.plugins: Dict[str, ToolPlugin] = {}
        # Get enabled tools from config, or empty set if not specified (load all by default)
        tools_config = config.get('tools', [])
        if tools_config:
            # If tools are explicitly configured, only load enabled ones
            self.enabled_tools = {tool['name'] for tool in tools_config if tool.get('enabled', True)}
            self.disabled_tools = {tool['name'] for tool in tools_config if not tool.get('enabled', True)}
        else:
            # If no tools config, load all tools by default
            self.enabled_tools = None  # None means load all
            self.disabled_tools = set()
    
    def load_plugins(self):
        """Load all plugins from tools/ and plugins/ directories"""
        # Load built-in tools
        self._load_from_directory('tools')
        
        # Load custom plugins
        self._load_from_directory('plugins')
        
        if self.enabled_tools is None:
            print(f"Loaded {len(self.plugins)} tools (all available)")
        else:
            print(f"Enabled tools: {', '.join(self.enabled_tools)}")
    
    def _load_from_directory(self, directory: str):
        """Load plugins from a directory"""
        plugin_dir = Path(directory)
        
        if not plugin_dir.exists():
            plugin_dir.mkdir(exist_ok=True)
            return
        
        # Find all Python files
        for plugin_file in plugin_dir.glob('*.py'):
            if plugin_file.name.startswith('__'):
                continue

            try:
                # Import module by file path without modifying sys.path
                module_name = plugin_file.stem
                spec = importlib.util.spec_from_file_location(
                    module_name, str(plugin_file.absolute())
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find ToolPlugin subclasses
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (issubclass(obj, ToolPlugin) and 
                        obj != ToolPlugin and 
                        not inspect.isabstract(obj)):
                        
                        # Instantiate plugin
                        plugin = obj()
                        
                        # Load if:
                        # 1. enabled_tools is None (load all by default), OR
                        # 2. tool is in enabled_tools, AND
                        # 3. tool is not explicitly disabled
                        should_load = (
                            (self.enabled_tools is None or plugin.name in self.enabled_tools) and
                            plugin.name not in self.disabled_tools
                        )
                        
                        if should_load:
                            self.plugins[plugin.name] = plugin
                            print(f"  ✓ Loaded: {plugin.name} - {plugin.description}")
                        
            except Exception as e:
                print(f"  ✗ Failed to load {plugin_file.name}: {e}")
    
    async def execute_tool(self, tool_name: str, parameters: Dict[str, Any]) -> Any:
        """Execute a tool by name"""
        if tool_name not in self.plugins:
            raise ValueError(f"Tool '{tool_name}' not found or not enabled")

        plugin = self.plugins[tool_name]

        # Normalize target/url parameters for backward compatibility
        # FIX: BUG-033 - Parameter Naming Inconsistency
        # Tools use either 'target' or 'url' - normalize so both work
        parameters = self._normalize_parameters(parameters)

        # Coerce parameter types to match schema before validation
        # FIX: BUG-493 - String "2" rejected where integer 2 expected
        parameters = self._coerce_parameter_types(parameters, plugin.schema)

        # Validate parameters
        if not plugin.validate_parameters(parameters):
            raise ValueError(f"Invalid parameters for tool '{tool_name}'")

        # Pass agent reference to plugin for progress reporting
        parameters['_agent'] = self.agent

        # Execute
        return await plugin.execute(parameters)
    
    def get_tool_schema(self, tool_name: str) -> Dict[str, Any]:
        """Get the schema for a tool"""
        if tool_name not in self.plugins:
            return None
        
        return self.plugins[tool_name].schema
    
    def list_tools(self):
        """List all loaded tools"""
        return [
            {
                'name': plugin.name,
                'description': plugin.description,
                'schema': plugin.schema,
                'metadata': plugin.metadata,
            }
            for plugin in self.plugins.values()
        ]

    def _coerce_parameter_types(self, parameters: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Coerce parameter values to match schema-declared types.

        FIX: BUG-493 - katana:crawl_depth2 param schema mismatch
        Workflow params often arrive as strings (from JSON forms, HTML inputs, etc.)
        even when the schema expects integer or boolean. This coerces them in-place
        so validation and tool execution receive the correct types.
        """
        if not schema or schema.get("type") != "object":
            return parameters

        properties = schema.get("properties", {})
        coerced = dict(parameters)

        for field, value in coerced.items():
            if field.startswith("_") or field not in properties:
                continue
            expected_type = properties[field].get("type")
            if not expected_type or not isinstance(value, str):
                continue

            if expected_type == "integer":
                try:
                    coerced[field] = int(value)
                except (ValueError, TypeError):
                    pass  # Let validation catch the real error
            elif expected_type == "boolean":
                lower = value.lower()
                if lower in ("true", "1"):
                    coerced[field] = True
                elif lower in ("false", "0"):
                    coerced[field] = False

        return coerced

    def _normalize_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize target/url/domain/host/ip/query parameters for backward compatibility.

        FIX: BUG-033 - Parameter Naming Inconsistency Across Agent Tools

        Tools use inconsistent parameter names:
        - 'target': nmap, httpx, subfinder, dns, shodan, testssl
        - 'url': katana, dalfox, sqlmap, commix, gowitness
        - 'domain': darkweb:monitor, subfinder, waybackurls, brand tools
        - 'host': some network tools
        - 'ip': shodan:host_lookup
        - 'query': shodan:search

        This method ensures all common target-like keys are populated from
        whichever key the workflow provided, so tools receive the parameter
        name they expect.
        """
        # Create a copy to avoid mutating the original
        normalized = dict(parameters)

        # Determine the canonical target value from whichever key is present
        canonical = (
            normalized.get('target')
            or normalized.get('url')
            or normalized.get('domain')
            or normalized.get('host')
            or normalized.get('ip')
        )

        if canonical:
            # Populate missing target-like keys
            for key in ('target', 'url', 'domain', 'host'):
                if key not in normalized:
                    normalized[key] = canonical

            # Only populate 'ip' if the value looks like an IP address
            if 'ip' not in normalized:
                import re
                if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', str(canonical)):
                    normalized['ip'] = canonical

        return normalized


"""
Layered Browser Login Tool

Tries scripted login first (fast, $0 cost), then falls back to AI login
if scripted fails (timeout, selector not found, login error).
Reports which method was used.
"""

import time
from typing import Dict, Any
from plugin_interface import ToolPlugin


class LayeredBrowserLoginTool(ToolPlugin):

    @property
    def name(self) -> str:
        return "authentication:layered_login"

    @property
    def description(self) -> str:
        return (
            "Authentication - Layered Login: Tries fast scripted login first ($0), "
            "then automatically falls back to AI-driven login if scripted fails."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "loginUrl": {
                    "type": "string",
                    "description": "URL of the login page",
                },
                "username": {
                    "type": "string",
                    "description": "Username for login",
                },
                "password": {
                    "type": "string",
                    "description": "Password for login",
                },
                "selectors": {
                    "type": "object",
                    "properties": {
                        "usernameField": {
                            "type": "string",
                            "description": "CSS selector for username input field",
                        },
                        "passwordField": {
                            "type": "string",
                            "description": "CSS selector for password input field",
                        },
                        "submitButton": {
                            "type": "string",
                            "description": "CSS selector for submit button",
                        },
                        "successIndicator": {
                            "type": "string",
                            "description": "CSS selector for element that appears after successful login (optional)",
                        },
                    },
                    "required": ["usernameField", "passwordField", "submitButton"],
                },
                "loginInstructions": {
                    "type": "string",
                    "description": "Natural language instructions for AI fallback",
                },
                "fallbackEnabled": {
                    "type": "boolean",
                    "description": "Enable AI fallback when scripted login fails",
                    "default": True,
                },
                "fallbackTimeoutMs": {
                    "type": "integer",
                    "description": "How long to wait for scripted login before falling back (ms)",
                    "default": 15000,
                },
                "headless": {
                    "type": "boolean",
                    "description": "Run browser in headless mode",
                    "default": True,
                },
                "mfaAutoFillTimeout": {
                    "type": "integer",
                    "description": "Seconds to poll for OTP auto-fill (AI fallback)",
                    "default": 60,
                },
                "debugScreenshots": {
                    "type": "boolean",
                    "description": "Save debug screenshots",
                    "default": False,
                },
                "executionId": {
                    "type": "string",
                    "description": "Unique execution ID for output file naming",
                },
                "timeoutMs": {
                    "type": "integer",
                    "description": "Scripted login timeout in milliseconds",
                    "default": 10000,
                },
            },
            "required": ["loginUrl", "username", "password", "selectors"],
        }

    @property
    def metadata(self):
        return {
            "category": "auth",
            "phase": 0,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["session"],
            "chainable_after": [],
            "chainable_before": ["katana:", "nuclei:", "sqlmap:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        from tools.scripted_browser_login import ScriptedBrowserLoginTool
        from tools.browser_login_ai import BrowserLoginAiTool

        fallback_enabled = parameters.get("fallbackEnabled", True)
        start_time = time.time()

        # Use fallbackTimeoutMs as the scripted login timeout if provided
        fallback_timeout = parameters.get("fallbackTimeoutMs", 15000)
        scripted_params = {**parameters, "timeoutMs": fallback_timeout}

        # Step 1: Try scripted login
        print("[Layered Login] Attempting scripted login first...")
        scripted_tool = ScriptedBrowserLoginTool()
        scripted_result = await scripted_tool.execute(scripted_params)

        if scripted_result.get("success"):
            total_time = time.time() - start_time
            print(f"[Layered Login] Scripted login succeeded in {total_time:.2f}s")
            return {
                **scripted_result,
                "login_method": "layered",
                "primary_method": "scripted",
                "fallback_used": False,
                "fallback_reason": None,
            }

        # Step 2: If scripted failed and fallback disabled, return failure
        if not fallback_enabled:
            print("[Layered Login] Scripted login failed, fallback disabled")
            return {
                **scripted_result,
                "login_method": "layered",
                "primary_method": "scripted",
                "fallback_used": False,
                "fallback_reason": None,
            }

        # Step 3: Fall back to AI login
        scripted_error = scripted_result.get("error", "Unknown scripted login failure")
        print(f"[Layered Login] Scripted login failed: {scripted_error}")
        print("[Layered Login] Falling back to AI login...")

        ai_tool = BrowserLoginAiTool()
        ai_result = await ai_tool.execute(parameters)

        total_time = time.time() - start_time
        ai_success = ai_result.get("success") or ai_result.get("status") == "SUCCESS"
        print(
            f"[Layered Login] AI fallback {'succeeded' if ai_success else 'failed'} "
            f"in {total_time:.2f}s total"
        )

        return {
            **ai_result,
            "login_method": "layered",
            "primary_method": "scripted",
            "fallback_used": True,
            "fallback_reason": scripted_error,
        }


def get_tool():
    return LayeredBrowserLoginTool()

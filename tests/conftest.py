"""Pytest bootstrap for the agent test suite.

Ensures `agent/` (the parent of this `tests/` dir) is on `sys.path` so test
modules can `from tools.* import` / `from lib.* import` regardless of the
invocation CWD. Previously each test self-inserted this; centralizing it here
lets test files (including the probe tests relocated from the agent root) just
import their targets directly.
"""
import os
import sys

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

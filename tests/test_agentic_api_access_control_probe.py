"""Locks for the #319 privilege-field mass-assignment phase of api:access_control_probe.

The tool is read-only by default; under aggressive:true + engagement:lab it attempts
role/is_admin mass-assignment on object-update endpoints and confirms via GET read-back
before flagging. These tests use a stateful in-memory user store (subclass override of
the network methods _fetch/_write) so the read-back confirmation path is exercised end
to end without any real HTTP.
"""

import json
import re
import unittest

from tools.agentic_api_access_control_probe import ApiAccessControlProbeTool


class FakeStoreTool(ApiAccessControlProbeTool):
    """api:access_control_probe wired to an in-memory /api/users/<id> store.

    `vulnerable=True` mirrors the HTB Facts / vulnlab fixture: any client-supplied
    role/is_admin field is mass-assigned with no whitelist and no ownership check.
    `vulnerable=False` accepts writes (HTTP 200) but never mutates state — the
    read-back FP-kill must reject these.
    """

    def __init__(self):
        super().__init__()
        self.store = {
            1: {"id": 1, "username": "admin", "email": "admin@lab.test", "role": "admin"},
            2: {"id": 2, "username": "user", "email": "user@lab.test", "role": "user"},
            3: {"id": 3, "username": "jdoe", "email": "jdoe@lab.test", "role": "user"},
        }
        self.write_calls = []
        self.vulnerable = True

    @staticmethod
    def _uid(url):
        match = re.search(r"/api/users/(\d+)", url)
        return int(match.group(1)) if match else None

    def _json_response(self, url, uid, method=None):
        body = json.dumps(self.store[uid])
        out = {
            "url": url,
            "status": 200,
            "headers": {"Content-Type": "application/json"},
            "body": body,
            "elapsedMs": 1,
            "jsonKeys": self._json_keys(body),
            "bodyLength": len(body),
            "sensitiveBodyMarkers": self._sensitive_body_markers(body),
        }
        if method:
            out["method"] = method
        return out

    @staticmethod
    def _not_found(url, method=None):
        out = {
            "url": url, "status": 404, "headers": {}, "body": "",
            "elapsedMs": 1, "jsonKeys": [], "bodyLength": 0, "sensitiveBodyMarkers": [],
        }
        if method:
            out["method"] = method
        return out

    async def _discover_readonly_endpoints(self, target, parameters, max_endpoints):
        return []  # keep the unit test fully offline

    async def _fetch(self, session, method, url, headers):
        uid = self._uid(url)
        if uid is None or uid not in self.store:
            return self._not_found(url)
        return self._json_response(url, uid)

    async def _write(self, session, method, url, kind, payload, headers):
        self.write_calls.append({"method": method, "url": url, "kind": kind, "payload": payload})
        uid = self._uid(url)
        if uid is None or uid not in self.store:
            return self._not_found(url, method)
        if self.vulnerable and isinstance(payload, dict):
            merged = {}
            for key, value in payload.items():
                if isinstance(value, dict):
                    merged.update(value)  # JSON-nested {"user": {...}}
                else:
                    nested = re.match(r"^\w+\[(\w+)\]$", str(key))  # form user[role]
                    merged[nested.group(1) if nested else key] = value
            if "role" in merged:
                self.store[uid]["role"] = str(merged["role"])
            for bool_field in ("is_admin", "admin", "isAdmin", "is_staff", "is_superuser", "superuser"):
                if bool_field in merged and str(merged[bool_field]).lower() in ("true", "1", "yes"):
                    self.store[uid]["role"] = "admin"
        return self._json_response(url, uid, method)


def _params(**extra):
    base = {"target": "http://lab.test/", "urls": ["http://lab.test/api/users/2"],
            "includeAnonymousComparison": False, "includeIdMutation": False}
    base.update(extra)
    return base


def _privesc_findings(result):
    return [f for f in result["findings"] if f.get("template-id") == "xasm-api-mass-assignment-privesc"]


class GateTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_is_read_only_no_writes(self):
        tool = FakeStoreTool()
        result = await tool.execute(_params())
        self.assertEqual(tool.write_calls, [])
        self.assertFalse(result["summary"]["privilegeMutationRan"])
        self.assertEqual(tool.store[2]["role"], "user")
        self.assertEqual(_privesc_findings(result), [])

    async def test_aggressive_without_lab_stays_read_only(self):
        tool = FakeStoreTool()
        result = await tool.execute(_params(aggressive=True, engagement="safe"))
        self.assertEqual(tool.write_calls, [])
        self.assertFalse(result["summary"]["privilegeMutationRan"])

    async def test_lab_without_aggressive_stays_read_only(self):
        tool = FakeStoreTool()
        result = await tool.execute(_params(aggressive=False, engagement="lab"))
        self.assertEqual(tool.write_calls, [])
        self.assertFalse(result["summary"]["privilegeMutationRan"])

    async def test_include_flag_disables_phase(self):
        tool = FakeStoreTool()
        result = await tool.execute(
            _params(aggressive=True, engagement="lab", includePrivilegeMutation=False)
        )
        self.assertEqual(tool.write_calls, [])
        self.assertFalse(result["summary"]["privilegeMutationRan"])


class MutationTests(unittest.IsolatedAsyncioTestCase):
    async def test_confirmed_self_privesc_is_critical(self):
        tool = FakeStoreTool()
        result = await tool.execute(_params(aggressive=True, engagement="lab"))
        self.assertTrue(result["summary"]["privilegeMutationRan"])
        findings = _privesc_findings(result)
        self_findings = [f for f in findings if f["evidence"]["scope"] == "self-id"]
        self.assertTrue(self_findings, "expected a self-id privilege-escalation finding")
        finding = self_findings[0]
        self.assertEqual(finding["info"]["severity"], "critical")
        self.assertEqual(finding["matcher-name"], "privilege-field-mass-assignment-confirmed")
        self.assertIn("mass-assignment", finding["info"]["tags"])
        self.assertIn("CWE-915", finding["info"]["classification"]["cwe-id"])
        self.assertIn("API3:2023", finding["info"]["classification"]["owasp"])
        # best-effort restore leaves the object as found
        self.assertEqual(tool.store[2]["role"], "user")

    async def test_neighbor_id_bola_write_flagged(self):
        tool = FakeStoreTool()
        result = await tool.execute(_params(aggressive=True, engagement="lab"))
        findings = _privesc_findings(result)
        scopes = {f["evidence"]["scope"] for f in findings}
        self.assertIn("self-id", scopes)
        self.assertIn("neighbor-id", scopes)
        neighbor = next(f for f in findings if f["evidence"]["scope"] == "neighbor-id")
        self.assertEqual(neighbor["matcher-name"], "neighbor-object-privilege-write")
        self.assertIn("bola", neighbor["info"]["tags"])

    async def test_readback_fp_kill_write_200_but_no_change(self):
        tool = FakeStoreTool()
        tool.vulnerable = False  # writes return 200 but never change state
        result = await tool.execute(_params(aggressive=True, engagement="lab"))
        self.assertTrue(tool.write_calls, "writes should still be attempted")
        self.assertEqual(_privesc_findings(result), [], "a write 200 alone must never flag")

    async def test_already_admin_self_not_flagged(self):
        tool = FakeStoreTool()
        result = await tool.execute(
            _params(urls=["http://lab.test/api/users/1"],
                    objectUpdatePaths=["/api/users/1"],
                    aggressive=True, engagement="lab")
        )
        self_findings = [
            f for f in _privesc_findings(result) if f["evidence"]["scope"] == "self-id"
            and f["matched-at"].endswith("/api/users/1")
        ]
        self.assertEqual(self_findings, [], "an already-admin object can't prove escalation")

    async def test_rails_nested_encoding_attempted_first_for_role(self):
        tool = FakeStoreTool()
        await tool.execute(_params(aggressive=True, engagement="lab"))
        nested = [c for c in tool.write_calls if "user[role]" in str(c["payload"])]
        self.assertTrue(nested, "Rails-nested user[role]=admin payload must be attempted")
        self.assertEqual(nested[0]["kind"], "form")

    async def test_session_cookie_redacted_in_findings(self):
        tool = FakeStoreTool()
        result = await tool.execute(
            _params(aggressive=True, engagement="lab",
                    authCookies="vulnlab.sid=SUPERSECRETTOKEN")
        )
        self.assertTrue(_privesc_findings(result))
        blob = json.dumps(result["findings"])
        self.assertNotIn("SUPERSECRETTOKEN", blob)
        self.assertIn("[REDACTED]", blob)


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.tool = ApiAccessControlProbeTool()

    def test_rails_resource_singularizes_collection(self):
        self.assertEqual(self.tool._rails_resource("http://x/admin/users/1"), "user")
        self.assertEqual(self.tool._rails_resource("http://x/api/accounts/2"), "account")
        self.assertEqual(self.tool._rails_resource("http://x/api/people/3"), "person")

    def test_payloads_cover_form_and_json_for_role(self):
        payloads = self.tool._mass_assignment_payloads("http://x/admin/users/1", "role")
        kinds = {kind for kind, _, _ in payloads}
        self.assertEqual(kinds, {"form", "json"})
        # Rails-nested form is present
        self.assertTrue(any(p == {"user[role]": "admin"} for _, p, _ in payloads))
        # injected value for a string field is the literal admin
        self.assertTrue(all(inj == "admin" for _, _, inj in payloads))

    def test_payloads_use_boolean_true_for_is_admin(self):
        payloads = self.tool._mass_assignment_payloads("http://x/api/users/1", "is_admin")
        self.assertTrue(all(inj is True for _, _, inj in payloads))

    def test_values_equal_handles_bool_and_string_shapes(self):
        self.assertTrue(self.tool._values_equal("admin", "admin"))
        self.assertTrue(self.tool._values_equal("true", True))
        self.assertTrue(self.tool._values_equal(True, True))
        self.assertFalse(self.tool._values_equal("user", "admin"))
        self.assertFalse(self.tool._values_equal(None, "admin"))
        self.assertFalse(self.tool._values_equal("false", True))

    def test_extract_field_value_reads_nested_json(self):
        resp = {"body": json.dumps({"data": {"user": {"role": "admin"}}})}
        self.assertEqual(self.tool._extract_field_value(resp, "role"), "admin")
        self.assertIsNone(self.tool._extract_field_value({"body": "<html>not json</html>"}, "role"))


if __name__ == "__main__":
    unittest.main()

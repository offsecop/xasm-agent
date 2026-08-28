import json
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import urlencode

from tools.agentic_exploitation_queue import (
    SERVER_ADAPTIVE_PROBE_CATALOG_KEY,
    ExploitationQueueTool,
)
from tools.web_adaptive_http_probe import (
    EXPECTED_BUDGETS,
    EXPECTED_LABELS,
    SERVER_PLAN_KEY,
    WebAdaptiveHttpProbeTool,
)
from tools.web_http_request_sequence import SERVER_POLICY_KEY


ORIGIN = "https://app.example.test"


def _policy():
    return {
        "version": 1,
        "allowedOrigins": [ORIGIN],
        "allowedIpRanges": [],
        "allowedPortRanges": [{"from": 443, "to": 443}],
        "maxRedirects": 3,
        "maxSteps": 50,
        "maxResponseBytes": 65_536,
        "requirePerHopValidation": True,
    }


def _urls():
    values = ("1", "2", "'", "''", "1")
    return [f"{ORIGIN}/search?{urlencode({'q': value})}" for value in values]


def _plan(*, method="GET", budgets=None, urls=None, skipped=None, parameter_name="q"):
    request_urls = urls or _urls()
    return {
        "version": 1,
        "templateId": "scalar-syntax-repair-v1",
        "origin": ORIGIN,
        "units": [
            {
                "unitId": "unit-1",
                "candidateId": "cand-0123456789abcdef",
                "artifactKind": "request-candidate",
                "surfaceClass": "parameterized-url",
                "parameterName": parameter_name,
                "requests": [
                    {"label": label, "method": method, "url": url}
                    for label, url in zip(EXPECTED_LABELS, request_urls)
                ],
            }
        ],
        "skipped": skipped or [],
        "budgets": dict(EXPECTED_BUDGETS if budgets is None else budgets),
    }


def _parameters(**overrides):
    result = {
        "target": ORIGIN + "/",
        "engagement": "standard",
        "allowUnsafeMethods": False,
        SERVER_PLAN_KEY: _plan(),
        SERVER_POLICY_KEY: _policy(),
    }
    result.update(overrides)
    return result


def _response(body, *, status=200, success=True, error=None):
    result = {
        "success": success,
        "url": ORIGIN + "/search?q=runtime",
        "method": "GET",
        "status": status,
        "headers": {
            "Content-Type": "text/plain",
            "Set-Cookie": "session=server-secret-value; Path=/; HttpOnly",
        },
        "body": body,
        "bodyBytes": len(body.encode("utf-8")),
        "truncated": False,
        "requestHeaders": {
            "Accept": "*/*",
            "Authorization": "Bearer auth-secret-value",
            "Cookie": "seed=seed-secret-value",
        },
        "requestBody": "",
        "redirects": [],
    }
    if error:
        result["error"] = error
    return result


class WebAdaptiveHttpProbeTests(unittest.IsolatedAsyncioTestCase):
    async def _execute_with(self, responses, parameters=None):
        tool = WebAdaptiveHttpProbeTool()
        with patch.object(
            tool, "_execute_one", new=AsyncMock(side_effect=responses)
        ) as execute_one, patch(
            "tools.web_adaptive_http_probe.asyncio.sleep", new=AsyncMock()
        ):
            output = await tool.execute(parameters or _parameters())
        return output, execute_one

    async def test_private_envelopes_are_schema_declared_and_missing_plan_fails_closed(self):
        tool = WebAdaptiveHttpProbeTool()
        self.assertIn(SERVER_PLAN_KEY, tool.schema["properties"])
        self.assertIn(SERVER_POLICY_KEY, tool.schema["properties"])
        self.assertTrue(tool.schema["properties"][SERVER_PLAN_KEY]["x-private"])

        output = await tool.execute({"target": ORIGIN + "/"})

        self.assertFalse(output["success"])
        self.assertEqual(output["coverageStatus"], "INCOMPLETE")
        self.assertEqual(output["code"], "SERVER_ADAPTIVE_PROBE_ENVELOPE_REQUIRED")
        self.assertNotIn("findings", output)

    async def test_empty_plan_is_rejected_instead_of_reporting_zero_request_success(self):
        empty_plan = _plan()
        empty_plan["units"] = []

        output, execute_one = await self._execute_with(
            [], _parameters(**{SERVER_PLAN_KEY: empty_plan})
        )

        self.assertFalse(output["success"])
        self.assertEqual(output["coverageStatus"], "INCOMPLETE")
        self.assertEqual(output["code"], "SERVER_ADAPTIVE_PROBE_ENVELOPE_DENY")
        execute_one.assert_not_awaited()

    async def test_plan_budget_method_and_origin_divergence_are_rejected_before_io(self):
        divergent = dict(EXPECTED_BUDGETS)
        divergent["maxRequests"] = 51
        cases = [
            _parameters(**{SERVER_PLAN_KEY: _plan(budgets=divergent)}),
            _parameters(**{SERVER_PLAN_KEY: _plan(method="POST")}),
            _parameters(
                **{
                    SERVER_PLAN_KEY: _plan(
                        urls=[
                            "https://other.example.test/search?q=x",
                            *_urls()[1:],
                        ]
                    )
                }
            ),
        ]
        for parameters in cases:
            with self.subTest(parameters=parameters[SERVER_PLAN_KEY]):
                output, execute_one = await self._execute_with([], parameters)
                self.assertFalse(output["success"])
                self.assertEqual(output["code"], "SERVER_ADAPTIVE_PROBE_ENVELOPE_DENY")
                execute_one.assert_not_awaited()

    async def test_closed_differential_confirms_only_body_and_error_repair_evidence(self):
        responses = [
            _response("result=ok; value=1"),
            _response("result=ok; value=2"),
            _response("SQL syntax error near value='", status=500),
            _response("result=ok; value=''") ,
            _response("result=ok; value=1"),
        ]
        parameters = _parameters(
            authCookies="seed=seed-secret-value",
            authHeaders={"Authorization": "Bearer auth-secret-value"},
        )

        output, execute_one = await self._execute_with(responses, parameters)

        self.assertTrue(output["success"], output)
        self.assertEqual(output["coverageStatus"], "CONFIRMED")
        self.assertEqual(output["orderedUnitIds"], ["unit-1"])
        self.assertEqual(execute_one.await_count, 5)
        self.assertEqual(
            [call.args[2].label for call in execute_one.await_args_list],
            list(EXPECTED_LABELS),
        )
        self.assertTrue(
            all(
                call.args[1].max_redirects <= 3
                and call.args[1].max_response_bytes <= 65_536
                for call in execute_one.await_args_list
            )
        )
        outcome = output["outcomes"][0]
        self.assertEqual(outcome["status"], "CONFIRMED")
        self.assertEqual(
            set(outcome),
            {"unitId", "candidateId", "templateId", "status", "differential", "evidence"},
        )
        self.assertEqual(
            set(outcome["differential"]),
            {
                "baselineReplayStable",
                "benignEquivalent",
                "syntaxBreakChangedBody",
                "syntaxRepairRecovered",
                "statusOnly",
                "errorFamily",
            },
        )
        self.assertTrue(outcome["differential"]["baselineReplayStable"])
        self.assertTrue(outcome["differential"]["benignEquivalent"])
        self.assertTrue(outcome["differential"]["syntaxBreakChangedBody"])
        self.assertTrue(outcome["differential"]["syntaxRepairRecovered"])
        self.assertFalse(outcome["differential"]["statusOnly"])
        self.assertEqual(outcome["differential"]["errorFamily"], "SQL_SYNTAX")
        self.assertEqual(
            [item["label"] for item in outcome["evidence"]["exchanges"]],
            list(EXPECTED_LABELS),
        )
        self.assertEqual(outcome["templateId"], "scalar-syntax-repair-v1")
        first_exchange = outcome["evidence"]["exchanges"][0]
        self.assertEqual(
            set(first_exchange["request"]),
            {"method", "url", "headers", "bodyLength"},
        )
        self.assertEqual(
            set(first_exchange["response"]),
            {
                "status",
                "headers",
                "body",
                "bodySha256",
                "bodyLength",
                "truncated",
                "elapsedMs",
            },
        )
        self.assertNotIn("findings", output)
        serialized = json.dumps(output)
        for secret in (
            "server-secret-value",
            "auth-secret-value",
            "seed-secret-value",
        ):
            self.assertNotIn(secret, serialized)
        self.assertEqual(
            first_exchange["request"]["headers"]["Authorization"],
            "***REDACTED***",
        )
        self.assertEqual(
            first_exchange["request"]["headers"]["Cookie"],
            "***REDACTED***",
        )
        self.assertEqual(
            first_exchange["response"]["headers"]["Set-Cookie"],
            "***REDACTED***",
        )

    async def test_status_only_and_reflection_only_differences_emit_no_finding(self):
        status_only = [
            _response("same body", status=status)
            for status in (200, 200, 500, 200, 200)
        ]
        reflected = [
            _response(f"stable page reflected={value}")
            for value in ("1", "2", "'", "''", "1")
        ]

        for responses, status_only_expected in ((status_only, True), (reflected, False)):
            with self.subTest(responses=responses):
                output, _execute_one = await self._execute_with(responses)
                self.assertTrue(output["success"], output)
                self.assertEqual(output["outcomes"][0]["status"], "NO_DIFFERENTIAL")
                self.assertEqual(
                    output["outcomes"][0]["differential"]["statusOnly"],
                    status_only_expected,
                )
                self.assertEqual(output["coverageStatus"], "COMPLETE_NO_FINDING")
                self.assertNotIn("findings", output)

    async def test_changed_body_without_a_novel_error_is_signal_not_finding(self):
        responses = [
            _response("result=ok; value=1"),
            _response("result=ok; value=2"),
            _response("input rejected by validation; value='", status=422),
            _response("result=ok; value=''") ,
            _response("result=ok; value=1"),
        ]

        output, _execute_one = await self._execute_with(responses)

        self.assertTrue(output["success"], output)
        self.assertEqual(output["outcomes"][0]["status"], "SIGNAL")
        self.assertEqual(output["coverageStatus"], "COMPLETE_NO_FINDING")
        self.assertNotIn("findings", output)

    async def test_path_parameter_reflection_is_neutralized(self):
        values = ("1", "2", "'", "''", "1")
        urls = [f"{ORIGIN}/items/{value}" for value in values]
        parameters = _parameters(
            **{
                SERVER_PLAN_KEY: _plan(urls=urls, parameter_name="itemId"),
            }
        )
        responses = [
            _response(f"stable page reflected={value}") for value in values
        ]

        output, _execute_one = await self._execute_with(responses, parameters)

        self.assertTrue(output["success"], output)
        self.assertEqual(output["outcomes"][0]["status"], "NO_DIFFERENTIAL")
        self.assertEqual(output["coverageStatus"], "COMPLETE_NO_FINDING")

    async def test_partial_transport_is_incomplete_and_never_claims_a_finding(self):
        responses = [
            _response("result=ok; value=1"),
            _response("result=ok; value=2"),
            _response("", success=False, error="connection reset"),
        ]

        output, execute_one = await self._execute_with(responses)

        self.assertTrue(output["success"])
        self.assertEqual(output["coverageStatus"], "INCOMPLETE")
        self.assertEqual(output["coverage"]["stopReason"], "HTTP_EXECUTION_FAILED")
        self.assertEqual(output["coverage"]["requestsRun"], 3)
        self.assertEqual(execute_one.await_count, 3)
        self.assertEqual(output["outcomes"][0]["status"], "INCOMPLETE")
        self.assertEqual(len(output["outcomes"][0]["evidence"]["exchanges"]), 2)
        self.assertNotIn("differential", output["outcomes"][0])
        self.assertNotIn("findings", output)

    async def test_evidence_truncation_completes_the_job_with_incomplete_coverage(self):
        responses = [
            _response("A" * (EXPECTED_BUDGETS["maxEvidenceBodyBytes"] + 1)),
            _response("result=ok; value=2"),
            _response("SQL syntax error near value='", status=500),
            _response("result=ok; value=''"),
            _response("result=ok; value=1"),
        ]

        output, execute_one = await self._execute_with(responses)

        self.assertTrue(output["success"])
        self.assertEqual(output["coverageStatus"], "INCOMPLETE")
        self.assertEqual(output["coverage"]["stopReason"], "EVIDENCE_BODY_TRUNCATED")
        self.assertEqual(output["coverage"]["requestsRun"], 5)
        self.assertEqual(execute_one.await_count, 5)
        self.assertEqual(output["outcomes"][0]["status"], "INCOMPLETE")
        self.assertEqual(
            output["outcomes"][0]["reasonCode"],
            "EVIDENCE_BODY_TRUNCATED",
        )
        self.assertNotIn("findings", output)

    async def test_transport_truncation_on_fifth_response_is_a_completed_incomplete_unit(self):
        responses = [
            _response("result=ok; value=1"),
            _response("result=ok; value=2"),
            _response("SQL syntax error near value='", status=500),
            _response("result=ok; value=''"),
            _response("result=ok; value=1"),
        ]
        responses[-1]["truncated"] = True

        output, execute_one = await self._execute_with(responses)

        self.assertTrue(output["success"])
        self.assertEqual(output["coverageStatus"], "INCOMPLETE")
        self.assertEqual(output["coverage"]["stopReason"], "RESPONSE_TRUNCATED")
        self.assertEqual(output["coverage"]["requestsRun"], 5)
        self.assertEqual(execute_one.await_count, 5)
        self.assertEqual(output["outcomes"][0]["status"], "INCOMPLETE")
        self.assertEqual(output["outcomes"][0]["reasonCode"], "RESPONSE_TRUNCATED")
        self.assertEqual(len(output["outcomes"][0]["evidence"]["exchanges"]), 5)
        self.assertNotIn("differential", output["outcomes"][0])
        self.assertNotIn("findings", output)


class ExploitationQueueAdaptiveProbeTests(unittest.IsolatedAsyncioTestCase):
    def _catalog(self):
        return {
            "version": 1,
            "maxCandidates": 20,
            "items": [
                {
                    "candidateId": "cand-0123456789abcdef",
                    "artifactKind": "request-candidate",
                    "surfaceClass": "parameterized-url",
                    "parameterName": "q",
                    "source": "browser-artifact",
                },
                {
                    "candidateId": "cand-fedcba9876543210",
                    "artifactKind": "html-form",
                    "surfaceClass": "form",
                    "parameterName": "search",
                    "source": "form-artifact",
                },
            ],
        }

    async def test_queue_emits_content_free_ready_decision_from_private_catalog(self):
        result = await ExploitationQueueTool().execute(
            {
                "target": ORIGIN + "/",
                SERVER_ADAPTIVE_PROBE_CATALOG_KEY: self._catalog(),
            }
        )

        self.assertTrue(result["success"], result)
        action = next(
            item for item in result["nextActions"] if item["tool"] == "web:adaptive_http_probe"
        )
        self.assertTrue(action["autonomousReady"])
        self.assertEqual(action["parameters"], {"target": ORIGIN + "/"})
        self.assertEqual(
            action["nativeProbe"],
            {
                "version": 1,
                "status": "READY",
                "adapterId": "web:adaptive_http_probe",
                "resolverVersion": 1,
                "candidateIds": [
                    "cand-0123456789abcdef",
                    "cand-fedcba9876543210",
                ],
                "candidateKinds": ["adaptive_http_candidate"],
                "confidence": 0.8,
                "source": "exploitation-queue",
            },
        )
        serialized = json.dumps(result)
        self.assertNotIn("browser-artifact", serialized)
        self.assertNotIn("form-artifact", serialized)
        self.assertNotIn("parameterized-url", serialized)
        self.assertNotIn("artifactRef", serialized)

    async def test_queue_rejects_catalog_content_fields_without_echoing_them(self):
        catalog = self._catalog()
        catalog["items"][0]["url"] = "https://secret.example.test/path"

        result = await ExploitationQueueTool().execute(
            {
                "target": ORIGIN + "/",
                SERVER_ADAPTIVE_PROBE_CATALOG_KEY: catalog,
            }
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["code"], "SERVER_ADAPTIVE_PROBE_CATALOG_DENY")
        self.assertNotIn("secret.example.test", json.dumps(result))

    async def test_queue_without_catalog_preserves_existing_behavior(self):
        result = await ExploitationQueueTool().execute({"target": ORIGIN + "/"})

        self.assertTrue(result["success"])
        self.assertNotIn(
            "web:adaptive_http_probe",
            [item["tool"] for item in result["nextActions"]],
        )


if __name__ == "__main__":
    unittest.main()

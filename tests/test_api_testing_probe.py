import hashlib
import json
import unittest

from aiohttp import web

from tools.api_testing_probe import (
    LAB_PROOF,
    MASS_ASSIGNMENT_MODE,
    MODE,
    RUNTIME_PROOF,
    ApiTestingProbeTool,
    _redact,
)


class _Server:
    def __init__(self, app):
        self.app = app
        self.runner = None

    async def __aenter__(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}/"

    async def __aexit__(self, exc_type, exc, tb):
        await self.runner.cleanup()


def _openapi(*, include_tuple=True, allow_delete=True):
    paths = {}
    if include_tuple:
        paths = {
            "/api/users/me": {
                "get": {
                    "operationId": "getCurrentUser",
                    "responses": {"200": {"description": "self"}},
                }
            },
            "/api/users": {
                "get": {
                    "operationId": "listVisibleUsers",
                    "responses": {"200": {"description": "list"}},
                }
            },
            "/api/users/{id}": {
                "parameters": [
                    {
                        "name": "id", "in": "path", "required": True,
                        "schema": {"type": "integer", "enum": [1, 2, 3]},
                    }
                ],
                "get": {
                    "operationId": "getUser",
                    "responses": {"200": {"description": "object"}},
                },
            },
        }
        if allow_delete:
            paths["/api/users/{id}"]["delete"] = {
                "operationId": "deleteUser",
                "responses": {"204": {"description": "deleted"}},
            }
    return {
        "openapi": "3.0.3", "info": {"title": "fixture", "version": "1"},
        "components": {"securitySchemes": {"session": {"type": "apiKey", "in": "cookie", "name": "session"}}},
        "security": [{"session": []}],
        "paths": paths,
    }


def _fixture(
    *, include_tuple=True, public_foreign=False, unstable=False,
    private=True, include_secret=True, allow_delete=True, require_auth=True,
):
    secret = "foreign-owner-secret-97d60f77"
    state = {"solved": False, "deletes": 0, "direct_reads": 0, "authenticated_reads": 0}
    app = web.Application()

    def authenticated(request):
        return not require_auth or request.headers.get("Cookie") == "session=server-owned-secret"

    async def root(_request):
        marker = "is-solved" if state["solved"] else "is-notsolved"
        return web.Response(text=f"<html><body class='{marker}'><a href='/openapi.json'>API</a></body></html>")

    async def docs(_request):
        return web.json_response(_openapi(include_tuple=include_tuple, allow_delete=allow_delete))

    async def self_object(request):
        if not authenticated(request):
            return web.Response(status=401)
        state["authenticated_reads"] += 1
        return web.json_response({"id": 1, "isPrivate": False, "ownerSecret": "self-safe-value"})

    async def list_objects(request):
        if not authenticated(request):
            return web.Response(status=401)
        rows = [{"id": 1}]
        if public_foreign:
            rows.append({"id": 2})
        return web.json_response(rows)

    async def direct(request):
        if not authenticated(request):
            return web.Response(status=401)
        object_id = int(request.match_info["id"])
        if object_id != 2:
            return web.Response(status=404, text="not found")
        state["direct_reads"] += 1
        value = secret + ("-changed" if unstable and state["direct_reads"] > 1 else "")
        row = {"id": 2, "isPrivate": private}
        if include_secret:
            row["recoveryCode"] = value
        return web.json_response(row)

    async def delete(request):
        if not authenticated(request):
            return web.Response(status=401)
        state["deletes"] += 1
        if int(request.match_info["id"]) == 2:
            state["solved"] = True
            return web.Response(status=204)
        return web.Response(status=404)

    app.router.add_get("/", root)
    app.router.add_get("/openapi.json", docs)
    app.router.add_get("/api/users/me", self_object)
    app.router.add_get("/api/users", list_objects)
    app.router.add_get("/api/users/{id}", direct)
    app.router.add_delete("/api/users/{id}", delete)
    return app, state, secret


def _mass_fixture(
    *, docs=True, discount=True, solve=True, require_auth=True,
):
    state = {"solved": False, "cart": False, "writes": 0, "checkout_posts": 0}
    app = web.Application()

    def authenticated(request):
        return not require_auth or request.headers.get("Cookie") == "session=mass-secret"

    async def root(_request):
        marker = "is-solved" if state["solved"] else "is-notsolved"
        status_text = "Solved" if state["solved"] else "Not solved"
        return web.Response(
            text=(
                f"<html><body class='{marker}'><span>{status_text}</span>"
                "<div class='product'><h3>Small item</h3><div class='price'>$10.00</div>"
                "<a href='/product?productId=2'>View details</a></div>"
                "<div class='product'><h3>Lightweight l33t Leather Jacket</h3>"
                "<div class='price'>$1337.00</div>"
                "<a href='/product?productId=1'>View details</a></div></body></html>"
            )
        )

    async def api_index(request):
        if not authenticated(request):
            return web.Response(status=401)
        if not docs:
            return web.Response(status=404)
        return web.Response(
            text=(
                "<html><body><a href='/api/doc/Order'>Order</a>"
                "<code>GET /checkout</code><code>POST /checkout</code></body></html>"
            )
        )

    async def order_doc(request):
        if not authenticated(request):
            return web.Response(status=401)
        body = "<html><h1>Order</h1><code>chosen_products</code>"
        if discount:
            body += "<code>chosen_discount</code><code>percentage</code><code>default: 0</code>"
        return web.Response(text=body + "</html>")

    async def product(request):
        return web.Response(
            text=(
                "<html><form id=addToCartForm method=POST action=/cart>"
                "<input type=hidden name=productId value=1>"
                "<input type=hidden name=redir value=PRODUCT>"
                "<input type=number name=quantity value=1>"
                "</form></html>"
            )
        )

    async def cart(request):
        if not authenticated(request):
            return web.Response(status=401)
        form = await request.post()
        if dict(form) != {"productId": "1", "redir": "PRODUCT", "quantity": "1"}:
            return web.Response(status=400)
        state["writes"] += 1
        state["cart"] = True
        return web.Response(status=302, headers={"Location": "/cart"})

    def order():
        value = {"chosen_products": []}
        if discount:
            value["chosen_discount"] = {"percentage": 0}
        if state["cart"]:
            value["chosen_products"] = [
                {"product_id": "1", "quantity": 1, "item_price": 133700}
            ]
        return value

    async def checkout(request):
        if not authenticated(request):
            return web.Response(status=401)
        if request.method == "GET":
            return web.json_response(order())
        payload = await request.json()
        expected = order()
        if discount:
            expected["chosen_discount"]["percentage"] = 100
        if payload != expected:
            return web.json_response({"error": "bad clone"}, status=400)
        state["writes"] += 1
        state["checkout_posts"] += 1
        if solve:
            state["solved"] = True
        return web.json_response({"order_status": "confirmed"}, status=201)

    app.router.add_get("/", root)
    app.router.add_get("/api/", api_index)
    app.router.add_get("/api/doc/Order", order_doc)
    app.router.add_get("/product", product)
    app.router.add_post("/cart", cart)
    app.router.add_route("*", "/api/checkout", checkout)
    return app, state


class ApiTestingProbeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tool = ApiTestingProbeTool()

    def test_schema_is_closed_and_exposes_no_model_controlled_request_shape(self):
        schema = self.tool.schema
        self.assertEqual(self.tool.name, "api:testing_probe")
        self.assertEqual(self.tool.metadata["category"], "dast-api")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["required"], ["target"])
        self.assertEqual(schema["properties"]["mode"]["enum"], [MODE])
        self.assertEqual(
            schema["properties"]["proofLevel"]["enum"], [RUNTIME_PROOF, LAB_PROOF]
        )
        for forbidden in (
            "path", "paths", "endpoint", "endpoints", "id", "ids", "method", "methods",
            "body", "payload", "field", "fields", "headers", "cookie", "answer",
        ):
            self.assertNotIn(forbidden, schema["properties"])
        for internal in (
            "allowMassAssignmentDiscountFallback", "authCookies", "authHeaders",
        ):
            self.assertTrue(schema["properties"][internal]["x-hidden"])
            self.assertTrue(schema["properties"][internal]["x-workflow-owned"])

    def test_long_authorized_host_is_preserved_while_credentials_are_redacted(self):
        host = "0ade00c004f6676e82bae319005f00f6.web-security-academy.net"
        transcript = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            "Cookie: session=server-owned-secret\r\n\r\n"
        )

        sanitized = _redact(transcript)

        self.assertIn(f"Host: {host}", sanitized)
        self.assertIn("Cookie: <redacted-runtime-secret>", sanitized)
        self.assertNotIn("server-owned-secret", sanitized)

    async def test_url_only_runtime_proves_documented_private_foreign_object(self):
        app, state, secret = _fixture()
        async with _Server(app) as target:
            result = await self.tool.execute(
                {"target": target, "authCookies": "session=server-owned-secret"}
            )

        self.assertTrue(result["success"])
        self.assertTrue(result["verified"])
        self.assertFalse(result["fallback"])
        self.assertEqual(result["proofLevel"], RUNTIME_PROOF)
        proof = result["verification"]
        self.assertEqual(proof["mode"], MODE)
        self.assertTrue(proof["listContainsSelf"])
        self.assertTrue(proof["listOmittedForeignObject"])
        self.assertTrue(proof["directForeignObjectReturned"])
        self.assertTrue(proof["repeatStable"])
        self.assertTrue(proof["nonexistentControlRejected"])
        self.assertTrue(proof["networkDestinationPreserved"])
        self.assertTrue(proof["destinationIpPinned"])
        self.assertEqual(proof["idField"], "id")
        self.assertEqual(proof["privateField"], "isPrivate")
        self.assertEqual(proof["sensitiveField"], "recoveryCode")
        self.assertEqual(proof["sensitiveValueSha256"], hashlib.sha256(secret.encode()).hexdigest())
        self.assertEqual(proof["sensitiveValueLength"], len(secret))
        labels = [step["label"] for step in proof["apiEvidence"]["steps"]]
        self.assertEqual(
            labels,
            [
                "api-root-baseline", "api-random-path-negative-control",
                "api-documentation-discovery", "api-self-object-control", "api-list-control",
                "api-direct-not-found-control", "api-foreign-object-proof",
                "api-foreign-object-repeat",
            ],
        )
        serialized = json.dumps(result)
        self.assertNotIn(secret, serialized)
        self.assertNotIn("server-owned-secret", serialized)
        self.assertNotIn("set-cookie", serialized.lower())
        expected = f"[REDACTED sha256={hashlib.sha256(secret.encode()).hexdigest()} len={len(secret)}]"
        self.assertIn(expected, proof["apiEvidence"]["steps"][6]["response"])
        for step in proof["apiEvidence"]["steps"]:
            self.assertEqual(step["authContextSha256"], proof["authContextSha256"])
            self.assertEqual(step["requestSha256"], hashlib.sha256(step["request"].encode()).hexdigest())
            self.assertEqual(step["responseSha256"], hashlib.sha256(step["response"].encode()).hexdigest())
        self.assertEqual(state["deletes"], 0)

    async def test_anonymous_fixed_principal_can_be_proved_from_only_the_root_url(self):
        app, state, secret = _fixture(require_auth=False)
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["verified"])
        self.assertRegex(result["verification"]["authContextSha256"], r"^[0-9a-f]{64}$")
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(state["deletes"], 0)

    async def test_lab_delete_requires_all_server_flags_and_documented_delete(self):
        app, state, secret = _fixture()
        async with _Server(app) as target:
            result = await self.tool.execute(
                {
                    "target": target, "authCookies": "session=server-owned-secret",
                    "proofLevel": LAB_PROOF, "engagement": "lab",
                    "allowUnsafeMethods": True, "stateChangeApproved": True,
                    "solutionSubmitApproved": True,
                }
            )
        self.assertTrue(result["verified"])
        self.assertEqual(result["proofLevel"], LAB_PROOF)
        self.assertTrue(result["verification"]["effectTriggered"])
        self.assertTrue(result["verification"]["labSolvedTransition"])
        self.assertEqual(result["requestCount"], 11)
        self.assertEqual(state["deletes"], 1)
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(
            [s["label"] for s in result["verification"]["apiEvidence"]["steps"]][-3:],
            ["lab-unsolved-control", "lab-approved-delete-submit", "lab-solved-confirmation"],
        )

    async def test_no_authentication_returns_verified_no_finding_without_object_reads(self):
        app, state, _secret = _fixture()
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target})
        self.assertTrue(result["success"])
        self.assertFalse(result["verified"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(state["authenticated_reads"], 0)

    async def test_documentation_without_secured_tuple_is_not_finding(self):
        app, _state, _secret = _fixture(include_tuple=False)
        async with _Server(app) as target:
            result = await self.tool.execute(
                {"target": target, "authCookies": "session=server-owned-secret"}
            )
        self.assertFalse(result["verified"])
        self.assertEqual(result["findings"], [])

    async def test_object_present_in_list_is_public_not_authz_differential(self):
        app, _state, _secret = _fixture(public_foreign=True)
        async with _Server(app) as target:
            result = await self.tool.execute(
                {"target": target, "authCookies": "session=server-owned-secret"}
            )
        self.assertFalse(result["verified"])
        self.assertEqual(result["findings"], [])

    async def test_unstable_repeat_is_not_proof(self):
        app, _state, _secret = _fixture(unstable=True)
        async with _Server(app) as target:
            result = await self.tool.execute(
                {"target": target, "authCookies": "session=server-owned-secret"}
            )
        self.assertFalse(result["verified"])
        self.assertEqual(result["findings"], [])

    async def test_unsafe_flags_cannot_delete_outside_lab_or_without_every_flag(self):
        for overrides in (
            {"proofLevel": RUNTIME_PROOF, "engagement": "lab", "allowUnsafeMethods": True,
             "stateChangeApproved": True, "solutionSubmitApproved": True},
            {"proofLevel": LAB_PROOF, "engagement": "standard", "allowUnsafeMethods": True,
             "stateChangeApproved": True, "solutionSubmitApproved": True},
            {"proofLevel": LAB_PROOF, "engagement": "lab", "allowUnsafeMethods": True,
             "stateChangeApproved": True, "solutionSubmitApproved": False},
        ):
            app, state, _secret = _fixture()
            async with _Server(app) as target:
                result = await self.tool.execute(
                    {"target": target, "authCookies": "session=server-owned-secret", **overrides}
                )
            self.assertTrue(result["verified"])
            self.assertEqual(state["deletes"], 0)

        app, state, _secret = _fixture(allow_delete=False)
        async with _Server(app) as target:
            result = await self.tool.execute(
                {
                    "target": target, "authCookies": "session=server-owned-secret",
                    "proofLevel": LAB_PROOF, "engagement": "lab", "allowUnsafeMethods": True,
                    "stateChangeApproved": True, "solutionSubmitApproved": True,
                }
            )
        self.assertTrue(result["verified"])
        self.assertEqual(state["deletes"], 0)

    async def test_private_or_sensitive_shape_is_required(self):
        for options in ({"private": False}, {"include_secret": False}):
            app, _state, _secret = _fixture(**options)
            async with _Server(app) as target:
                result = await self.tool.execute(
                    {"target": target, "authCookies": "session=server-owned-secret"}
                )
            self.assertFalse(result["verified"])

    async def test_url_only_lab_mass_assignment_discount_solves_with_two_bounded_posts(self):
        app, state = _mass_fixture()
        parameters = {
            "authCookies": "session=mass-secret", "proofLevel": LAB_PROOF,
            "engagement": "lab", "allowUnsafeMethods": True,
            "stateChangeApproved": True, "solutionSubmitApproved": True,
            "allowMassAssignmentDiscountFallback": True,
        }
        async with _Server(app) as target:
            result = await self.tool.execute({"target": target, **parameters})

        self.assertTrue(result["verified"])
        self.assertEqual(result["mode"], MASS_ASSIGNMENT_MODE)
        self.assertEqual(result["proofLevel"], LAB_PROOF)
        self.assertFalse(result["fallback"])
        verification = result["verification"]
        self.assertEqual(verification["discountFieldPath"], "chosen_discount.percentage")
        self.assertEqual(verification["originalPercentage"], 0)
        self.assertEqual(verification["injectedPercentage"], 100)
        self.assertEqual(verification["productPriceMinor"], 133700)
        self.assertEqual(verification["productField"], "productId")
        self.assertEqual(verification["quantityField"], "quantity")
        self.assertEqual(verification["stateChangingRequestCount"], 2)
        self.assertEqual(verification["stateChangingMethods"], ["POST", "POST"])
        self.assertTrue(verification["labSolvedTransition"])
        self.assertTrue(verification["cartFormObserved"])
        self.assertTrue(verification["checkoutSchemaVerified"])
        self.assertEqual(state["writes"], 2)
        cart_request = verification["apiEvidence"]["steps"][5]["request"]
        self.assertIn("productId=1&redir=PRODUCT&quantity=1", cart_request)
        self.assertEqual(
            result["findings"][0]["request"],
            verification["apiEvidence"]["steps"][7]["request"],
        )
        labels = [step["label"] for step in verification["apiEvidence"]["steps"]]
        self.assertEqual(
            labels,
            [
                "api-mass-assignment-root-unsolved-control",
                "api-mass-assignment-endpoint-documentation",
                "api-mass-assignment-order-schema",
                "api-mass-assignment-product-catalog",
                "api-mass-assignment-add-to-cart-form",
                "api-mass-assignment-cart-submit",
                "api-mass-assignment-checkout-baseline",
                "api-mass-assignment-discount-submit",
                "api-mass-assignment-solved-confirmation",
            ],
        )
        serialized = json.dumps(result)
        self.assertNotIn("mass-secret", serialized)
        self.assertNotIn("Cookie:", serialized)
        for step in verification["apiEvidence"]["steps"]:
            self.assertEqual(step["authContextSha256"], verification["authContextSha256"])
            self.assertEqual(step["requestSha256"], hashlib.sha256(step["request"].encode()).hexdigest())
            self.assertEqual(step["responseSha256"], hashlib.sha256(step["response"].encode()).hexdigest())

    async def test_mass_assignment_never_writes_without_lab_auth_and_all_gates(self):
        scenarios = [
            {"engagement": "lab", "proofLevel": LAB_PROOF,
             "allowUnsafeMethods": True, "stateChangeApproved": True,
             "solutionSubmitApproved": True, "authCookies": "session=mass-secret"},
            {"engagement": "standard", "proofLevel": RUNTIME_PROOF,
             "allowUnsafeMethods": True, "stateChangeApproved": True,
             "solutionSubmitApproved": True, "authCookies": "session=mass-secret",
             "allowMassAssignmentDiscountFallback": True},
            {"engagement": "lab", "proofLevel": LAB_PROOF,
             "allowUnsafeMethods": True, "stateChangeApproved": True,
             "solutionSubmitApproved": True,
             "allowMassAssignmentDiscountFallback": True},
            {"engagement": "lab", "proofLevel": LAB_PROOF,
             "allowUnsafeMethods": True, "stateChangeApproved": True,
             "solutionSubmitApproved": False, "authCookies": "session=mass-secret",
             "allowMassAssignmentDiscountFallback": True},
            {"engagement": "lab", "proofLevel": LAB_PROOF,
             "authCookies": "session=mass-secret",
             "allowMassAssignmentDiscountFallback": True},
        ]
        for parameters in scenarios:
            app, state = _mass_fixture()
            async with _Server(app) as target:
                result = await self.tool.execute({"target": target, **parameters})
            self.assertFalse(result["verified"])
            self.assertEqual(state["writes"], 0)

    async def test_mass_assignment_missing_docs_or_discount_never_writes(self):
        parameters = {
            "authCookies": "session=mass-secret", "proofLevel": LAB_PROOF,
            "engagement": "lab", "allowUnsafeMethods": True,
            "stateChangeApproved": True, "solutionSubmitApproved": True,
            "allowMassAssignmentDiscountFallback": True,
        }
        for options in ({"docs": False}, {"discount": False}):
            app, state = _mass_fixture(**options)
            async with _Server(app) as target:
                result = await self.tool.execute({"target": target, **parameters})
            self.assertFalse(result["verified"])
            self.assertEqual(state["writes"], 0)

    async def test_mass_assignment_without_solved_transition_is_not_finding(self):
        app, state = _mass_fixture(solve=False)
        async with _Server(app) as target:
            result = await self.tool.execute(
                {
                    "target": target, "authCookies": "session=mass-secret",
                    "proofLevel": LAB_PROOF, "engagement": "lab",
                    "allowUnsafeMethods": True, "stateChangeApproved": True,
                    "solutionSubmitApproved": True,
                    "allowMassAssignmentDiscountFallback": True,
                }
            )
        self.assertFalse(result["verified"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(state["writes"], 2)

    async def test_target_and_auth_reject_unsafe_input(self):
        for target in (
            "https://u:p@example.test/", "https://example.test/?x=1", "https://example.test/#x",
        ):
            result = await self.tool.execute({"target": target})
            self.assertFalse(result["success"])
        result = await self.tool.execute(
            {"target": "https://example.test/", "authHeaders": {"X-Target": "evil"}}
        )
        self.assertFalse(result["success"])


if __name__ == "__main__":
    unittest.main()

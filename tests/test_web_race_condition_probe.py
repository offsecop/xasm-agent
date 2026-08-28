import unittest
from unittest.mock import patch

from aiohttp import web

from tools.web_race_condition_probe import (
    MODE,
    RaceConditionProbeTool,
    build_race_step,
    extract_single_use_codes,
    is_single_use_form,
    validate_probe_parameters,
)


class RaceConditionProbeUnitTests(unittest.TestCase):
    def test_extracts_only_contextual_single_use_code(self):
        html = """
        <html><body>
          <nav>ACCOUNT CHECKOUT PORTSWIGGER</nav>
          <p>Summer coupon code: PROMO20</p>
        </body></html>
        """
        self.assertEqual(extract_single_use_codes(html), ["PROMO20"])

    def test_recognizes_urlencoded_coupon_form(self):
        self.assertTrue(
            is_single_use_form(
                {
                    "method": "POST",
                    "contentType": "application/x-www-form-urlencoded",
                    "url": "https://shop.test/cart/coupon",
                    "fields": {"csrf": "opaque", "coupon": ""},
                }
            )
        )
        self.assertFalse(
            is_single_use_form(
                {
                    "method": "POST",
                    "contentType": "application/json",
                    "url": "https://shop.test/cart/coupon",
                    "fields": {"coupon": ""},
                }
            )
        )

    def test_rejects_lab_finalization_outside_lab_or_ctf(self):
        valid, reason = validate_probe_parameters(
            {
                "target": "https://shop.test/",
                "mode": MODE,
                "proofLevel": "lab-state-change",
                "engagement": "aggressive",
                "allowUnsafeMethods": True,
                "stateChangeApproved": True,
                "authCookies": "session=opaque",
            }
        )
        self.assertFalse(valid)
        self.assertIn("lab or ctf", reason)

    def test_rejects_mismatched_server_session_aliases(self):
        valid, reason = validate_probe_parameters(
            {
                "target": "https://shop.test/",
                "mode": MODE,
                "proofLevel": "runtime-limit-overrun",
                "engagement": "aggressive",
                "allowUnsafeMethods": True,
                "stateChangeApproved": True,
                "authCookies": "session=one",
                "cookie": "session=two",
            }
        )
        self.assertFalse(valid)
        self.assertIn("server-injected", reason)

    def test_race_step_has_reproducible_request_and_response(self):
        step = build_race_step(
            "https://shop.test/cart/coupon",
            "csrf=secret&coupon=PROMO20",
            {
                "requestCount": 30,
                "completedStreams": 30,
                "releaseSendCalls": 1,
                "statusDistribution": {"200": 3, "400": 27},
                "responses": [
                    {"streamId": 1, "status": 200, "body": "Coupon applied"},
                    {"streamId": 3, "status": 400, "body": "Already applied"},
                ],
            },
            ["secret"],
        )
        self.assertIn("POST /cart/coupon HTTP/2", step["request"])
        self.assertIn("X-xASM-Single-Packet-Streams: 30", step["request"])
        self.assertNotIn("csrf=secret", step["request"])
        self.assertIn('"200": 3', step["response"])
        self.assertTrue(step["singlePacket"])
        self.assertEqual(step["releaseSendCalls"], 1)


class RaceConditionProbeFlowTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.state = {
            "item": False,
            "discounts": 0,
            "solved": False,
            "checkouts": 0,
            "confirmations": 0,
            "cartReads": 0,
        }
        app = web.Application()
        app.router.add_get("/", self._root)
        app.router.add_get("/product", self._product)
        app.router.add_post("/cart", self._add)
        app.router.add_get("/cart", self._cart)
        app.router.add_post("/cart/coupon", self._coupon)
        app.router.add_post("/cart/checkout", self._checkout)
        app.router.add_get("/cart/order-confirmation", self._confirmation)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()
        port = self.site._server.sockets[0].getsockname()[1]
        self.target = f"http://127.0.0.1:{port}/"

    async def asyncTearDown(self):
        await self.runner.cleanup()

    def _authenticated(self, request):
        return request.headers.get("Cookie") == "session=fixture"

    async def _root(self, request):
        if not self._authenticated(request):
            return web.Response(status=401, text="login required")
        status = "is-solved" if self.state["solved"] else "is-notsolved"
        text = "Congratulations, you solved the lab!" if self.state["solved"] else "Not solved"
        return web.Response(
            text=f"""
            <html><body><div class="widgetcontainer-lab-status {status}">{text}</div>
            <p>Use coupon code PROMO20 at checkout.</p>
            <a href="/product?productId=1">Jacket</a><a href="/cart">Cart</a>
            </body></html>
            """,
            content_type="text/html",
        )

    async def _product(self, request):
        if not self._authenticated(request):
            return web.Response(status=401)
        return web.Response(
            text="""
            <html><body><div class="product-price">$1337.00</div>
            <form method="POST" action="/cart">
              <input type="hidden" name="productId" value="1">
              <input type="hidden" name="redir" value="PRODUCT">
              <input type="number" name="quantity" value="1">
            </form></body></html>
            """,
            content_type="text/html",
        )

    async def _add(self, request):
        if not self._authenticated(request):
            return web.Response(status=401)
        form = await request.post()
        if form.get("productId") == "1":
            self.state["item"] = True
        # PortSwigger's real lab redirects back to the product detail after
        # adding the item.  The probe must re-read the observed POST action
        # (/cart), not mistake this navigation redirect for the state page.
        raise web.HTTPFound("/product?productId=1")

    async def _cart(self, request):
        if not self._authenticated(request):
            return web.Response(status=401)
        self.state["cartReads"] += 1
        if not self.state["item"]:
            return web.Response(text="<html><body>Cart is empty</body></html>", content_type="text/html")
        total = 1337.0 * (0.8 ** self.state["discounts"])
        coupon_rows = "".join("<li>PROMO20</li>" for _ in range(self.state["discounts"]))
        checkout = ""
        if total <= 100:
            checkout = """
            <form method="POST" action="/cart/checkout">
              <input type="hidden" name="csrf" value="checkout-csrf">
            </form>
            """
        return web.Response(
            text=f"""
            <html><body><table><tr><th>Total:</th><th>${total:.2f}</th></tr></table>
            <ul>{coupon_rows}</ul>
            <form method="POST" action="/cart/coupon">
              <input type="hidden" name="csrf" value="coupon-csrf">
              <input name="coupon">
            </form>{checkout}</body></html>
            """,
            content_type="text/html",
        )

    async def _coupon(self, request):
        if not self._authenticated(request):
            return web.Response(status=401)
        form = await request.post()
        if form.get("coupon") != "PROMO20":
            return web.Response(status=400, text="Invalid coupon")
        if self.state["discounts"]:
            return web.Response(status=400, text="Coupon already applied")
        self.state["discounts"] = 1
        return web.Response(text="Coupon applied")

    async def _checkout(self, request):
        if not self._authenticated(request):
            return web.Response(status=401)
        self.state["checkouts"] += 1
        total = 1337.0 * (0.8 ** self.state["discounts"])
        if total > 100:
            return web.Response(status=400, text="Insufficient funds")
        raise web.HTTPSeeOther("/cart/order-confirmation?order-confirmed=true")

    async def _confirmation(self, request):
        if not self._authenticated(request):
            return web.Response(status=401)
        self.state["confirmations"] += 1
        self.state["solved"] = True
        return web.Response(text="Order placed")

    def _race_result(self, *_args, **_kwargs):
        self.state["discounts"] = 15
        responses = [
            {"index": index, "streamId": index * 2 + 1, "status": 200, "headers": {}, "body": "Coupon applied"}
            for index in range(30)
        ]
        return {
            "protocol": "h2",
            "singlePacket": True,
            "releaseSendCalls": 1,
            "releaseBytes": 330,
            "requestCount": 30,
            "completedStreams": 30,
            "statusDistribution": {"200": 30},
            "responses": responses,
        }

    async def test_url_only_lab_flow_discovers_proves_and_solves(self):
        tool = RaceConditionProbeTool()
        with patch(
            "tools.web_race_condition_probe.h2_single_packet_race",
            side_effect=self._race_result,
        ):
            result = await tool.execute(
                {
                    "target": self.target,
                    "mode": MODE,
                    "proofLevel": "lab-state-change",
                    "engagement": "lab",
                    "allowUnsafeMethods": True,
                    "stateChangeApproved": True,
                    "authCookies": "session=fixture",
                    "cookie": "session=fixture",
                    "maxDiscoveryPages": 12,
                    "maxRaceRequests": 30,
                    "requestBudget": 64,
                    "timeoutSeconds": 10,
                }
            )

        self.assertTrue(result["success"], result)
        self.assertFalse(result["fallback"])
        self.assertEqual(result["total_findings"], 1)
        verification = result["verification"]
        self.assertTrue(verification["verified"])
        self.assertTrue(verification["singlePacket"])
        self.assertTrue(verification["multipleEffects"])
        self.assertTrue(verification["serialReplayRejected"])
        self.assertTrue(verification["solvedBefore"] is False)
        self.assertTrue(verification["solvedAfter"])
        self.assertGreaterEqual(self.state["cartReads"], 1)
        self.assertEqual(self.state["checkouts"], 1)
        self.assertEqual(self.state["confirmations"], 1)
        self.assertIn(
            "approved-lab-finalizer-confirmation",
            [step["label"] for step in verification["evidence"]],
        )
        finding = result["findings"][0]
        self.assertEqual(finding["info"]["classification"]["cwe-id"], ["CWE-362"])
        self.assertIn("POST /cart/coupon", finding["request"])
        self.assertIn("HTTP/2 synchronized response group", finding["response"])
        serialized = str(result)
        self.assertNotIn("coupon-csrf", serialized)
        self.assertNotIn("session=fixture", serialized)

    async def test_runtime_proof_never_calls_finalizer(self):
        tool = RaceConditionProbeTool()
        with patch(
            "tools.web_race_condition_probe.h2_single_packet_race",
            side_effect=self._race_result,
        ):
            result = await tool.execute(
                {
                    "target": self.target,
                    "mode": MODE,
                    "proofLevel": "runtime-limit-overrun",
                    "engagement": "aggressive",
                    "allowUnsafeMethods": True,
                    "stateChangeApproved": True,
                    "authCookies": "session=fixture",
                    "maxRaceRequests": 30,
                    "requestBudget": 64,
                    "timeoutSeconds": 10,
                }
            )

        self.assertEqual(result["total_findings"], 1)
        self.assertTrue(result["verification"]["verified"])
        self.assertIsNone(result["verification"]["solvedAfter"])
        self.assertEqual(self.state["checkouts"], 0)
        self.assertFalse(self.state["solved"])


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import AsyncMock, patch

from tools.web_security_controls_probe import WebSecurityControlsProbeTool


class _ClientSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class WebSecurityControlsMultiOriginTests(unittest.IsolatedAsyncioTestCase):
    async def test_checks_every_explicitly_confirmed_origin(self):
        requested = []

        async def fetch(_session, url, **_kwargs):
            requested.append(url)
            return {
                "url": url,
                "status": 200,
                "headers": {},
                "text": "<html></html>",
                "truncated": False,
            }

        targets = ["http://192.0.2.25/", "https://192.0.2.25/"]
        with (
            patch(
                "tools.web_security_controls_probe.aiohttp.TCPConnector",
                return_value=object(),
            ),
            patch(
                "tools.web_security_controls_probe.aiohttp.ClientSession",
                return_value=_ClientSession(),
            ),
            patch(
                "tools.web_security_controls_probe.fetch_text",
                new=AsyncMock(side_effect=fetch),
            ),
        ):
            result = await WebSecurityControlsProbeTool().execute(
                {
                    "urls": targets,
                    "discoverFromTarget": False,
                    "maxPages": 4,
                    "maxUrls": 4,
                }
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["targets"], targets)
        self.assertEqual(requested, targets)


if __name__ == "__main__":
    unittest.main()

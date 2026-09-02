import unittest
from unittest.mock import AsyncMock, patch

from tools.nmap_quick_scan import NmapQuickScanTool


class _CompletedNmapProcess:
    def __init__(self, stdout: str):
        self._stdout = stdout.encode("utf-8")

    async def communicate(self):
        return self._stdout, b""


class NmapQuickScanObservedHostTests(unittest.IsolatedAsyncioTestCase):
    async def test_cidr_results_keep_each_concrete_observed_host(self):
        xml_output = """<?xml version="1.0"?>
        <nmaprun>
          <host>
            <address addr="00:11:22:33:44:55" addrtype="mac" />
            <address addr="10.20.30.41" addrtype="ipv4" />
            <ports>
              <port protocol="tcp" portid="80">
                <state state="open" />
                <service name="http" product="nginx" />
              </port>
            </ports>
          </host>
          <host>
            <address addr="10.20.30.42" addrtype="ipv4" />
            <ports>
              <port protocol="tcp" portid="443">
                <state state="open" />
                <service name="https" />
              </port>
            </ports>
          </host>
        </nmaprun>"""

        with patch(
            "tools.nmap_quick_scan.asyncio.create_subprocess_exec",
            new_callable=AsyncMock,
            return_value=_CompletedNmapProcess(xml_output),
        ) as create_process:
            result = await NmapQuickScanTool().execute({"target": "10.20.30.0/24"})

        nmap_command = create_process.await_args.args
        self.assertIn("10.20.30.0/24", nmap_command)
        self.assertTrue(result["success"])
        open_ports = result["output"]["openPorts"]
        self.assertEqual(
            [entry["target"] for entry in open_ports],
            ["10.20.30.41", "10.20.30.42"],
        )
        self.assertEqual(
            [entry["originalTarget"] for entry in open_ports],
            ["10.20.30.0/24", "10.20.30.0/24"],
        )
        self.assertEqual([entry["port"] for entry in open_ports], [80, 443])


if __name__ == "__main__":
    unittest.main()

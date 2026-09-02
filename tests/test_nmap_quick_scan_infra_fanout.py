from tools.nmap_quick_scan import NmapQuickScanTool


def test_ipv4_cidr_is_preserved_for_nmap_discovery():
    tool = NmapQuickScanTool()

    assert tool._split_host_port("10.20.0.0/16") == ("10.20.0.0/16", None)


def test_cidr_xml_ports_are_attributed_to_each_observed_host():
    tool = NmapQuickScanTool()
    xml = """
    <nmaprun>
      <host>
        <address addr="10.20.1.10" addrtype="ipv4" />
        <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports>
      </host>
      <host>
        <address addr="10.20.1.11" addrtype="ipv4" />
        <ports><port protocol="tcp" portid="443"><state state="open"/><service name="http"/></port></ports>
      </host>
    </nmaprun>
    """

    ports = tool._parse_open_ports(xml, "10.20.0.0/16", "10.20.0.0/16")

    assert [(entry["target"], entry["port"]) for entry in ports] == [
        ("10.20.1.10", 80),
        ("10.20.1.11", 443),
    ]
    assert all(entry["originalTarget"] == "10.20.0.0/16" for entry in ports)

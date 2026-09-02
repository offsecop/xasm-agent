from tools.nmap_service_scan import FTP_LISTING_LIMIT, NmapServiceScanTool


def _xml(script_output: str | None) -> str:
    script = "" if script_output is None else f'<script id="ftp-anon" output="{script_output}" />'
    return f"""
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="21">
            <state state="open" />
            <service name="ftp" product="ProFTPD" />
            {script}
          </port>
        </ports>
      </host>
    </nmaprun>
    """


def test_positive_ftp_anon_nse_output_builds_one_bounded_finding():
    tool = NmapServiceScanTool()
    listing = "&#xa;".join(
        ["Anonymous FTP login allowed (FTP code 230)"]
        + [f"-rw-r--r-- 1 ftp ftp 10 Jan 01 00:00 file-{index}.txt" for index in range(30)]
    )

    service = tool._parse_nmap_output(_xml(listing), 21)
    finding = tool._build_ftp_anon_finding("192.0.2.25", 21, service)

    assert service["ftpAnon"]["verified"] is True
    assert service["ftpAnon"]["replyCode"] == 230
    assert len(service["ftpAnon"]["listing"]) == FTP_LISTING_LIMIT
    assert service["ftpAnon"]["listingTruncated"] is True
    assert finding is not None
    assert finding["template-id"] == "xasm-ftp-anonymous-access"
    assert finding["matched-at"] == "ftp://192.0.2.25:21/"
    assert finding["info"]["severity"] == "medium"
    assert "PASS [REDACTED]" in finding["request"]
    assert "FTP code 230" in finding["response"]
    assert len(finding["evidence"]["listing"]) == FTP_LISTING_LIMIT


def test_negative_or_absent_ftp_anon_output_does_not_build_a_finding():
    tool = NmapServiceScanTool()

    denied = tool._parse_nmap_output(
        _xml("Anonymous FTP login denied (FTP code 530)"),
        21,
    )
    absent = tool._parse_nmap_output(_xml(None), 21)

    assert "ftpAnon" not in denied
    assert "ftpAnon" not in absent
    assert tool._build_ftp_anon_finding("192.0.2.25", 21, denied) is None
    assert tool._build_ftp_anon_finding("192.0.2.25", 21, absent) is None


def test_malformed_nmap_xml_keeps_legacy_empty_service_behavior():
    tool = NmapServiceScanTool()

    service = tool._parse_nmap_output("<nmaprun>", 21)

    assert service == {}
    assert tool._build_ftp_anon_finding("192.0.2.25", 21, service) is None

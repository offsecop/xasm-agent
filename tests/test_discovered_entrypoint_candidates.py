import pytest

from tools.web_code_injection_probe import WebCodeInjectionProbeTool
from tools.web_header_injection_probe import WebHeaderInjectionProbeTool
from tools.web_ldap_injection_probe import WebLdapInjectionProbeTool
from tools.web_nosql_injection_probe import WebNoSqlInjectionProbeTool
from tools.web_xpath_injection_probe import WebXPathInjectionProbeTool


@pytest.mark.parametrize(
    ("tool_class", "entrypoint", "expected_parameter"),
    [
        (WebNoSqlInjectionProbeTool, "https://lab.example/filter?category=Gifts", "category"),
        (WebXPathInjectionProbeTool, "https://lab.example/filter?search=alice", "search"),
        (WebLdapInjectionProbeTool, "https://lab.example/users?filter=alice", "filter"),
        (WebCodeInjectionProbeTool, "https://lab.example/calculate?expr=7*7", "expr"),
        (WebHeaderInjectionProbeTool, "https://lab.example/redirect?url=home", "url"),
    ],
)
def test_server_selected_parameterized_entrypoint_is_a_candidate(
    tool_class, entrypoint, expected_parameter
):
    tool = tool_class()
    tool._max_body = 96_000

    candidates = tool._discover_candidates("<html></html>", entrypoint)

    assert candidates
    assert candidates[0][0] == entrypoint
    assert candidates[0][1] == expected_parameter

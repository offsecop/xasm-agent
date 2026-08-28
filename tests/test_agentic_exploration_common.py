from tools._agentic_exploration_common import (
    NATIVE_PROBE_PRIVATE_CANDIDATES_KEY,
    NATIVE_PROBE_QUERY_CANDIDATES_KEY,
    build_native_probe_query_contract,
    extract_html_map,
)


def test_html_map_keeps_signal_metadata_without_raw_form_defaults():
    html = """
    <html><body>
      <form action="/fetch?token=url-secret&amp;email=person%40example.test#private" method="post" enctype="application/x-www-form-urlencoded">
        <input name="email" type="email" value="person@example.test">
        <input name="csrfToken" type="hidden" value="csrf-secret-123">
        <input name="__VIEWSTATE" type="hidden" value="framework-state-secret">
        <select name="originFeed">
          <option value="https://inventory.example.test/stock?sku=1" selected>primary</option>
        </select>
        <textarea name="address">123 Private Street</textarea>
      </form>
    </body></html>
    """

    result = extract_html_map(html, "https://shop.example.test/")
    form = result["forms"][0]

    assert form["action"] == "https://shop.example.test/fetch?token=&email="
    assert form["method"] == "POST"
    assert form["contentType"] == "application/x-www-form-urlencoded"
    assert form["fields"] == [
        {
            "name": "email",
            "type": "email",
            "hasDefault": True,
            "valueLength": 19,
            "valueKind": "scalar",
            "valueSource": "html-default",
        },
        {
            "name": "csrfToken",
            "type": "hidden",
            "hasDefault": True,
            "valueLength": 15,
            "valueKind": "scalar",
            "valueSource": "html-default",
        },
        {
            "name": "__VIEWSTATE",
            "type": "hidden",
            "hasDefault": True,
            "valueLength": 22,
            "valueKind": "scalar",
            "valueSource": "html-default",
        },
        {
            "name": "address",
            "type": "textarea",
            "hasDefault": True,
            "valueLength": 18,
            "valueKind": "scalar",
            "valueSource": "html-default",
        },
        {
            "name": "originFeed",
            "type": "select",
            "hasDefault": True,
            "valueLength": 42,
            "valueKind": "absolute-http-url",
            "valueSource": "selected-option",
        },
    ]
    public_result = {
        key: value
        for key, value in result.items()
        if key != NATIVE_PROBE_PRIVATE_CANDIDATES_KEY
    }
    serialized = str(public_result)
    assert "person@example.test" not in serialized
    assert "csrf-secret-123" not in serialized
    assert "framework-state-secret" not in serialized
    assert "123 Private Street" not in serialized
    assert "inventory.example.test" not in serialized
    assert "url-secret" not in serialized
    private = result[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY][0]
    assert private["candidateId"] == form["nativeProbeCandidateId"]
    assert private["url"] == (
        "https://shop.example.test/fetch?"
        "token=url-secret&email=person%40example.test#private"
    )
    assert private["publicUrl"] == form["action"]
    assert private["fields"] == {
        "email": "person@example.test",
        "csrfToken": "csrf-secret-123",
        "__VIEWSTATE": "framework-state-secret",
        "address": "123 Private Street",
        "originFeed": "https://inventory.example.test/stock?sku=1",
    }


def test_html_map_does_not_treat_unchecked_controls_as_defaults():
    result = extract_html_map(
        """
        <form action="/" method="post">
          <input name="enabled" type="checkbox" value="yes">
          <input name="mode" type="radio" value="unsafe" checked>
          <input name="empty" value="">
        </form>
        """,
        "https://example.test/",
    )

    assert result["forms"][0]["fields"] == [
        {"name": "enabled", "type": "checkbox", "hasDefault": False},
        {
            "name": "mode",
            "type": "radio",
            "hasDefault": True,
            "valueLength": 6,
            "valueKind": "scalar",
            "valueSource": "html-default",
        },
        {
            "name": "empty",
            "type": "text",
            "hasDefault": True,
            "valueLength": 0,
            "valueKind": "empty",
            "valueSource": "html-default",
        },
    ]


def test_query_contract_keeps_values_only_in_private_lane():
    result = build_native_probe_query_contract(
        [
            "https://shop.example.test/search?q=private-term&page=2#fragment-secret",
            "https://shop.example.test/search?q=private-term&page=2#duplicate",
        ],
        source="param:discover",
    )

    public = result[NATIVE_PROBE_QUERY_CANDIDATES_KEY]
    assert len(public) == 1
    assert public[0]["url"] == "https://shop.example.test/search?q=&page="
    assert public[0]["parameterNames"] == ["q", "page"]
    assert "private-term" not in str(public)
    assert "fragment-secret" not in str(public)
    private = result[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY]
    assert private == [
        {
            "candidateId": public[0]["nativeProbeCandidateId"],
            "kind": "request-candidate",
            "url": "https://shop.example.test/search?q=private-term&page=2",
            "publicUrl": public[0]["url"],
            "method": "GET",
            "contentType": "application/x-www-form-urlencoded",
            "fields": {"q": "private-term", "page": "2"},
            "fieldTypes": {"q": "query", "page": "query"},
            "source": "param:discover",
        }
    ]

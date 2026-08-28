import json
from unittest.mock import AsyncMock, patch

import pytest

from tools._agentic_exploration_common import (
    NATIVE_PROBE_PATH_CANDIDATES_KEY,
    NATIVE_PROBE_PRIVATE_CANDIDATES_KEY,
    NATIVE_PROBE_QUERY_CANDIDATES_KEY,
)
from tools.agentic_api_discover import (
    ApiDiscoverTool,
    _documented_path_contract,
    _documented_query_contract,
)


def test_documented_get_query_uses_private_value_lane_and_public_redaction():
    result = _documented_query_contract(
        "https://api.example.test/",
        [
            {
                "method": "GET",
                "url": "https://api.example.test/api/transactions?account_number=42",
                "source": "openapi",
                "originalPath": "/api/transactions",
            }
        ],
    )

    public = result[NATIVE_PROBE_QUERY_CANDIDATES_KEY]
    assert public == [
        {
            "url": "https://api.example.test/api/transactions?account_number=",
            "method": "GET",
            "contentType": "application/x-www-form-urlencoded",
            "fields": [
                {
                    "name": "account_number",
                    "type": "query",
                    "hasDefault": True,
                    "valueLength": 2,
                    "valueKind": "scalar",
                    "valueSource": "documented-query",
                }
            ],
            "parameterNames": ["account_number"],
            "nativeProbeCandidateId": public[0]["nativeProbeCandidateId"],
            "source": "openapi",
            "originalPath": "/api/transactions",
        }
    ]
    assert "42" not in str(public)

    private = result[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY]
    assert private == [
        {
            "candidateId": public[0]["nativeProbeCandidateId"],
            "kind": "request-candidate",
            "url": "https://api.example.test/api/transactions?account_number=42",
            "publicUrl": public[0]["url"],
            "method": "GET",
            "contentType": "application/x-www-form-urlencoded",
            "fields": {"account_number": "42"},
            "fieldTypes": {"account_number": "query"},
            "source": "api:discover:openapi",
        }
    ]


def test_documented_query_contract_dedupes_shape_and_rejects_unsafe_candidates():
    result = _documented_query_contract(
        "https://api.example.test/",
        [
            {
                "method": "GET",
                "url": "https://api.example.test/search?q=first",
                "source": "openapi",
            },
            {
                "method": "GET",
                "url": "https://api.example.test/search?q=second",
                "source": "openapi-duplicate",
            },
            {
                "method": "POST",
                "url": "https://api.example.test/search?q=post",
                "source": "openapi",
            },
            {
                "method": "GET",
                "url": "https://other.example.test/search?q=cross-origin",
                "source": "openapi",
            },
            {
                "method": "GET",
                "url": "https://user:password@api.example.test/search?q=credentialed",
                "source": "openapi",
            },
            {
                "method": "GET",
                "url": "https://api.example.test/search?q=fragment#ignored",
                "source": "openapi",
            },
            {"method": "GET", "url": "not a url?q=broken", "source": "openapi"},
        ],
    )

    public = result[NATIVE_PROBE_QUERY_CANDIDATES_KEY]
    private = result[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY]
    assert len(public) == 1
    assert len(private) == 1
    assert public[0]["url"] == "https://api.example.test/search?q="
    assert private[0]["url"] == "https://api.example.test/search?q=first"


def test_documented_public_get_path_uses_private_value_lane_and_template_redaction():
    result = _documented_path_contract(
        "https://api.example.test/",
        [
            {
                "method": "GET",
                "url": "https://api.example.test/transactions/42",
                "pathTemplateUrl": "https://api.example.test/transactions/{account_number}",
                "pathParameters": ["account_number"],
                "queryParameters": [],
                "requiresAuth": False,
                "source": "openapi",
                "originalPath": "/transactions/{account_number}",
            }
        ],
    )

    public = result[NATIVE_PROBE_PATH_CANDIDATES_KEY]
    assert public == [
        {
            "url": "https://api.example.test/transactions/{account_number}",
            "method": "GET",
            "contentType": "application/x-www-form-urlencoded",
            "fields": [
                {
                    "name": "account_number",
                    "type": "path",
                    "hasDefault": True,
                    "valueLength": 2,
                    "valueKind": "scalar",
                    "valueSource": "documented-path",
                }
            ],
            "parameterNames": ["account_number"],
            "nativeProbeCandidateId": public[0]["nativeProbeCandidateId"],
            "source": "openapi",
            "originalPath": "/transactions/{account_number}",
        }
    ]
    assert "42" not in str(public)

    private = result[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY]
    assert private == [
        {
            "candidateId": public[0]["nativeProbeCandidateId"],
            "kind": "request-candidate",
            "url": "https://api.example.test/transactions/42",
            "publicUrl": public[0]["url"],
            "method": "GET",
            "contentType": "application/x-www-form-urlencoded",
            "fields": {"account_number": "42"},
            "fieldTypes": {"account_number": "path"},
            "source": "api:discover:openapi",
        }
    ]


def test_documented_path_contract_dedupes_and_rejects_unsafe_or_ambiguous_shapes():
    base = {
        "method": "GET",
        "url": "https://api.example.test/orders/42",
        "pathTemplateUrl": "https://api.example.test/orders/{id}",
        "pathParameters": ["id"],
        "queryParameters": [],
        "requiresAuth": False,
        "source": "openapi",
    }
    result = _documented_path_contract(
        "https://api.example.test/",
        [
            base,
            {**base, "url": "https://api.example.test/orders/99"},
            {**base, "method": "POST"},
            {**base, "requiresAuth": True},
            {**base, "url": "https://other.example.test/orders/42"},
            {**base, "url": "https://user:pass@api.example.test/orders/42"},
            {**base, "url": "https://api.example.test/orders/42?q=x"},
            {**base, "url": "https://api.example.test/orders/42#fragment"},
            {**base, "pathTemplateUrl": "https://api.example.test/orders/prefix-{id}"},
            {**base, "pathParameters": ["other"]},
        ],
    )

    assert len(result[NATIVE_PROBE_PATH_CANDIDATES_KEY]) == 1
    assert len(result[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY]) == 1


@pytest.mark.asyncio
async def test_api_discover_emits_documented_query_contract_at_top_level():
    document = {
        "openapi": "3.0.0",
        "info": {"title": "Example API", "version": "1"},
        "paths": {
            "/api/transactions": {
                "get": {
                    "parameters": [
                        {
                            "name": "account_number",
                            "in": "query",
                            "schema": {"type": "integer", "example": 42},
                        }
                    ]
                }
            },
            "/transactions/{account_number}": {
                "get": {
                    "security": [],
                    "parameters": [
                        {
                            "name": "account_number",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer", "example": 42},
                        }
                    ],
                }
            },
        },
    }
    fetched = {
        "url": "https://api.example.test/openapi.json",
        "status": 200,
        "headers": {"content-type": "application/json"},
        "text": json.dumps(document),
    }

    with patch(
        "tools.agentic_api_discover.fetch_text",
        new=AsyncMock(return_value=fetched),
    ):
        result = await ApiDiscoverTool().execute(
            {"target": "https://api.example.test/", "maxCandidates": 1}
        )

    assert result["summary"]["nativeQueryCandidates"] == 1
    assert result["summary"]["nativePathCandidates"] == 1
    assert result["parameterizedUrls"] == [
        "https://api.example.test/api/transactions?account_number="
    ]
    assert result[NATIVE_PROBE_QUERY_CANDIDATES_KEY][0]["parameterNames"] == [
        "account_number"
    ]
    assert result[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY][0]["fields"] == {
        "account_number": "42"
    }
    assert result[NATIVE_PROBE_PATH_CANDIDATES_KEY][0]["url"] == (
        "https://api.example.test/transactions/{account_number}"
    )
    assert result[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY][0]["fieldTypes"] == {
        "account_number": "path"
    }
    assert result[NATIVE_PROBE_PRIVATE_CANDIDATES_KEY][1]["fieldTypes"] == {
        "account_number": "query"
    }

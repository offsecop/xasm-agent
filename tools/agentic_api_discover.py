"""
API discovery for agentic exploration.

This tool intentionally turns API documentation into an attack map. When a
Swagger/OpenAPI document is found, it extracts concrete endpoints, methods,
parameters, and JSON body keys so downstream probes can test API authorization
and IDOR/BOLA candidates instead of merely reporting that documentation exists.
"""

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import aiohttp
import yaml

from plugin_interface import ToolPlugin
from tools._agentic_exploration_common import fetch_text, normalize_url, parse_headers, same_origin


COMMON_API_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/api-docs",
    "/api-docs",
    "/api/docs",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui/",
    "/swagger-ui/index.html",
    "/docs",
    "/redoc",
    "/graphql",
    "/api/graphql",
    "/graphiql",
    "/api",
    "/api/v1",
    "/api/v2",
]

HTTP_METHODS = {"get", "head", "post", "put", "patch", "delete", "options", "trace"}
READONLY_METHODS = {"GET", "HEAD", "OPTIONS"}
PATH_PARAM_RE = re.compile(r"\{([^{}]+)\}")


def _origin(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _dedupe_keep_order(values: Iterable[Any], limit: int = 500) -> List[Any]:
    seen: Set[str] = set()
    output: List[Any] = []
    for value in values:
        key = json.dumps(value, sort_keys=True, default=str) if isinstance(value, (dict, list)) else str(value)
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(value)
        if len(output) >= limit:
            break
    return output


def _safe_name(value: Any) -> str:
    return str(value or "").strip()


def _resolve_ref(document: Dict[str, Any], ref: str) -> Any:
    if not ref.startswith("#/"):
        return None
    cur: Any = document
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _dereference_schema(document: Dict[str, Any], schema: Any, depth: int = 0) -> Any:
    if depth > 8 or not isinstance(schema, dict):
        return schema
    if "$ref" in schema:
        resolved = _resolve_ref(document, str(schema.get("$ref")))
        if resolved is not None:
            return _dereference_schema(document, resolved, depth + 1)
    merged = dict(schema)
    for key in ("allOf", "anyOf", "oneOf"):
        variants = merged.get(key)
        if isinstance(variants, list):
            props: Dict[str, Any] = {}
            required: List[str] = []
            for item in variants:
                resolved = _dereference_schema(document, item, depth + 1)
                if isinstance(resolved, dict):
                    if isinstance(resolved.get("properties"), dict):
                        props.update(resolved["properties"])
                    if isinstance(resolved.get("required"), list):
                        required.extend(str(v) for v in resolved["required"])
            if props:
                merged.setdefault("properties", {}).update(props)
            if required:
                merged["required"] = _dedupe_keep_order(required, 50)
    return merged


def _schema_property_names(document: Dict[str, Any], schema: Any, limit: int = 16) -> List[str]:
    schema = _dereference_schema(document, schema)
    if not isinstance(schema, dict):
        return []
    if schema.get("type") == "array" and isinstance(schema.get("items"), dict):
        return _schema_property_names(document, schema["items"], limit)
    props = schema.get("properties")
    if isinstance(props, dict):
        return [str(k) for k in list(props.keys())[:limit]]
    additional = schema.get("additionalProperties")
    if isinstance(additional, dict):
        return _schema_property_names(document, additional, limit)
    return []


def _sample_for_param(name: str, schema: Any = None) -> str:
    schema = schema if isinstance(schema, dict) else {}
    for key in ("example", "default"):
        if key in schema and schema[key] not in (None, ""):
            return str(schema[key])
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return str(enum[0])
    lower = name.lower()
    if "email" in lower:
        return "test@example.com"
    if "pass" in lower:
        return "Password123!"
    if lower in {"q", "query", "search", "term", "keyword"}:
        return "test"
    if any(marker in lower for marker in ("amount", "price", "count", "page", "limit", "offset", "id", "uid")):
        return "1"
    if schema.get("type") in {"integer", "number"}:
        return "1"
    if schema.get("type") == "boolean":
        return "true"
    return "xasm"


def _replace_path_params(path: str, params: List[Dict[str, Any]]) -> Tuple[str, List[str]]:
    param_by_name = {str(p.get("name")): p for p in params if isinstance(p, dict) and p.get("in") == "path"}
    names: List[str] = []

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        names.append(name)
        schema = param_by_name.get(name, {}).get("schema") or param_by_name.get(name, {})
        return _sample_for_param(name, schema)

    return PATH_PARAM_RE.sub(repl, path), names


def _with_query_params(url: str, params: List[Dict[str, Any]], method: str) -> str:
    query_params = [p for p in params if isinstance(p, dict) and p.get("in") == "query" and p.get("name")]
    if not query_params:
        return url
    selected = [p for p in query_params if p.get("required")][:6]
    if not selected and method in READONLY_METHODS:
        selected = query_params[:4]
    if not selected:
        return url
    parsed = urlparse(url)
    existing = parse_qsl(parsed.query, keep_blank_values=True)
    existing_names = {name for name, _ in existing}
    additions = []
    for param in selected:
        name = str(param.get("name"))
        if name in existing_names:
            continue
        additions.append((name, _sample_for_param(name, param.get("schema") or param)))
    if not additions:
        return url
    return urlunparse(parsed._replace(query=urlencode(existing + additions, doseq=True)))


def _substitute_server_variables(url: str, variables: Any) -> str:
    if not isinstance(variables, dict):
        return url
    for name, meta in variables.items():
        default = meta.get("default") if isinstance(meta, dict) else None
        if default is not None:
            url = url.replace("{" + str(name) + "}", str(default))
    return url


def _resolve_server_bases(document: Dict[str, Any], target: str, spec_url: str) -> List[str]:
    target_origin = _origin(target) or _origin(spec_url)
    bases: List[str] = []
    servers = document.get("servers")
    if isinstance(servers, list):
        for server in servers:
            if not isinstance(server, dict):
                continue
            server_url = _safe_name(server.get("url"))
            if not server_url:
                continue
            server_url = _substitute_server_variables(server_url, server.get("variables"))
            bases.append(urljoin(target_origin + "/", server_url))
    if not bases and document.get("swagger"):
        host = _safe_name(document.get("host"))
        base_path = _safe_name(document.get("basePath")) or "/"
        schemes = document.get("schemes") if isinstance(document.get("schemes"), list) else []
        scheme = str(schemes[0]) if schemes else (urlparse(target or spec_url).scheme or "http")
        if host:
            bases.append(f"{scheme}://{host}{base_path}")
        else:
            bases.append(urljoin(target_origin + "/", base_path.lstrip("/")))
    if not bases:
        bases.append(target_origin)
    # Many public Swagger specs use production server URLs even when the same
    # spec is mirrored by a lab/staging host. Keep the current target origin as
    # a safe same-origin base so the platform tests the authorized host instead
    # of silently discarding all endpoints as cross-origin.
    bases.append(target_origin)
    return _dedupe_keep_order([b.rstrip("/") for b in bases if b], 20)


def _load_api_document(text: str) -> Optional[Dict[str, Any]]:
    if not text or len(text) > 3_000_000:
        return None
    stripped = text.strip()
    try:
        parsed = json.loads(stripped)
    except Exception:
        try:
            parsed = yaml.safe_load(stripped)
        except Exception:
            return None
    if not isinstance(parsed, dict):
        return None
    if not (parsed.get("openapi") or parsed.get("swagger") or isinstance(parsed.get("paths"), dict)):
        return None
    return parsed


def _extract_embedded_api_documents(text: str) -> List[Dict[str, Any]]:
    if not text:
        return []
    documents: List[Dict[str, Any]] = []
    decoder = json.JSONDecoder()
    # Swagger UI often embeds the full spec as `swaggerDoc: {...}` or
    # `"swaggerDoc": {...}` inside swagger-ui-init.js.
    for pattern in (r"""["']?swaggerDoc["']?\s*:""", r"""["']?spec["']?\s*:"""):
        for match in re.finditer(pattern, text[:2_500_000], re.I):
            cursor = match.end()
            while cursor < len(text) and text[cursor].isspace():
                cursor += 1
            if cursor >= len(text) or text[cursor] != "{":
                continue
            try:
                parsed, _end = decoder.raw_decode(text[cursor:])
            except Exception:
                continue
            if isinstance(parsed, dict) and (
                parsed.get("openapi") or parsed.get("swagger") or isinstance(parsed.get("paths"), dict)
            ):
                documents.append(parsed)
    return _dedupe_keep_order(documents, 8)


def _load_api_documents(text: str) -> List[Dict[str, Any]]:
    documents: List[Dict[str, Any]] = []
    direct = _load_api_document(text)
    if direct:
        documents.append(direct)
    documents.extend(_extract_embedded_api_documents(text))
    return _dedupe_keep_order(documents, 10)


def _operation_parameters(document: Dict[str, Any], path_item: Dict[str, Any], operation: Dict[str, Any]) -> List[Dict[str, Any]]:
    params: List[Dict[str, Any]] = []
    for source in (path_item.get("parameters"), operation.get("parameters")):
        if not isinstance(source, list):
            continue
        for param in source:
            if isinstance(param, dict) and "$ref" in param:
                resolved = _resolve_ref(document, str(param.get("$ref")))
                if isinstance(resolved, dict):
                    params.append(resolved)
            elif isinstance(param, dict):
                params.append(param)
    return params


def _request_body_keys(document: Dict[str, Any], operation: Dict[str, Any], params: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    keys: List[str] = []
    content_types: List[str] = []
    request_body = operation.get("requestBody")
    if isinstance(request_body, dict) and "$ref" in request_body:
        resolved = _resolve_ref(document, str(request_body.get("$ref")))
        if isinstance(resolved, dict):
            request_body = resolved
    if isinstance(request_body, dict):
        content = request_body.get("content")
        if isinstance(content, dict):
            for content_type, media in content.items():
                content_types.append(str(content_type))
                if isinstance(media, dict):
                    keys.extend(_schema_property_names(document, media.get("schema"), 24))
    for param in params:
        if not isinstance(param, dict):
            continue
        if param.get("in") == "body":
            keys.extend(_schema_property_names(document, param.get("schema"), 24))
        if param.get("in") == "formData" and param.get("name"):
            keys.append(str(param["name"]))
    return _dedupe_keep_order(keys, 24), _dedupe_keep_order(content_types, 12)


def parse_openapi_endpoints(
    document: Dict[str, Any],
    *,
    target: str,
    spec_url: str,
    include_cross_origin_servers: bool = False,
    max_endpoints: int = 300,
) -> List[Dict[str, Any]]:
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return []
    bases = _resolve_server_bases(document, target, spec_url)
    target_origin = _origin(target)
    endpoints: List[Dict[str, Any]] = []
    for raw_path, raw_path_item in paths.items():
        if not isinstance(raw_path_item, dict):
            continue
        for method_key, raw_operation in raw_path_item.items():
            method = str(method_key).lower()
            if method not in HTTP_METHODS or not isinstance(raw_operation, dict):
                continue
            method_upper = method.upper()
            params = _operation_parameters(document, raw_path_item, raw_operation)
            concrete_path, path_param_names = _replace_path_params(str(raw_path), params)
            query_param_names = [str(p.get("name")) for p in params if isinstance(p, dict) and p.get("in") == "query" and p.get("name")]
            body_keys, body_content_types = _request_body_keys(document, raw_operation, params)
            security = raw_operation.get("security", document.get("security"))
            requires_auth = bool(security) if security != [] else False
            for base in bases:
                full_url = base.rstrip("/") + "/" + concrete_path.lstrip("/")
                full_url = normalize_url(_with_query_params(full_url, params, method_upper))
                if target_origin and not include_cross_origin_servers and not same_origin(target, full_url):
                    continue
                endpoints.append(
                    {
                        "method": method_upper,
                        "url": full_url,
                        "path": urlparse(full_url).path or "/",
                        "originalPath": str(raw_path),
                        "operationId": _safe_name(raw_operation.get("operationId")),
                        "summary": _safe_name(raw_operation.get("summary") or raw_operation.get("description"))[:180],
                        "tags": raw_operation.get("tags") if isinstance(raw_operation.get("tags"), list) else [],
                        "source": "openapi",
                        "specUrl": spec_url,
                        "pathParameters": path_param_names,
                        "queryParameters": query_param_names,
                        "requestBodyKeys": body_keys,
                        "requestBodyContentTypes": body_content_types,
                        "requiresAuth": requires_auth,
                    }
                )
                if len(endpoints) >= max_endpoints:
                    return _dedupe_endpoints(endpoints, max_endpoints)
    return _dedupe_endpoints(endpoints, max_endpoints)


def _dedupe_endpoints(endpoints: Iterable[Dict[str, Any]], limit: int = 300) -> List[Dict[str, Any]]:
    seen: Set[str] = set()
    output: List[Dict[str, Any]] = []
    for endpoint in endpoints:
        method = str(endpoint.get("method") or "GET").upper()
        url = str(endpoint.get("url") or "")
        if not url:
            continue
        key = f"{method} {url}"
        if key in seen:
            continue
        seen.add(key)
        output.append(endpoint)
        if len(output) >= limit:
            break
    return output


def _extract_spec_refs_from_html(html: str, page_url: str) -> List[str]:
    if not html:
        return []
    refs: List[str] = []
    for match in re.finditer(r"""(?:url|configUrl)\s*[:=]\s*['"]([^'"]+)['"]""", html, re.I):
        refs.append(match.group(1))
    for match in re.finditer(r"""(?:href|src)\s*=\s*['"]([^'"]*(?:openapi|swagger|api-docs)[^'"]*)['"]""", html, re.I):
        refs.append(match.group(1))
    for match in re.finditer(r"""['"]((?:/|https?://)[^'"]*(?:openapi|swagger|api-docs)[^'"]*)['"]""", html, re.I):
        refs.append(match.group(1))
    output = []
    for ref in refs:
        if ref.startswith("data:") or ref.startswith("javascript:"):
            continue
        output.append(urljoin(page_url, ref))
    return _dedupe_keep_order(output, 30)


class ApiDiscoverTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "api:discover"

    @property
    def description(self) -> str:
        return "Discovers API surfaces and parses Swagger/OpenAPI docs into concrete endpoints for downstream API testing."

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "candidatePaths": {"type": "array", "items": {"type": "string"}},
                "maxCandidates": {"type": "integer", "default": 60},
                "maxEndpoints": {"type": "integer", "default": 300},
                "includeCrossOriginServers": {"type": "boolean", "default": False},
                "cookie": {"type": "string"},
                "authCookies": {"type": "string"},
                "headers": {"type": "object"},
                "authHeaders": {"type": "object"},
            },
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
        }

    @property
    def metadata(self):
        return {
            "category": "agentic-recon",
            "phase": 2,
            "domain": ["web", "api"],
            "input_type": ["url", "api_paths"],
            "output_type": ["api_endpoints", "openapi", "graphql"],
            "chainable_after": ["js:", "browser:", "katana:"],
            "chainable_before": ["curl:", "api:", "param:", "nuclei:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        target = normalize_url(parameters.get("target") or parameters.get("url"))
        if not target:
            return {"success": False, "error": "target is required"}
        max_candidates = max(1, min(int(parameters.get("maxCandidates") or 60), 160))
        max_endpoints = max(1, min(int(parameters.get("maxEndpoints") or 300), 800))
        include_cross_origin = bool(parameters.get("includeCrossOriginServers", False))
        agent = parameters.get("_agent")

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        candidates = list(COMMON_API_PATHS)
        if isinstance(parameters.get("candidatePaths"), list):
            candidates.extend(str(p) for p in parameters["candidatePaths"] if p)
        queue = self._dedupe_paths(candidates)

        if agent:
            agent.report_progress("Discovering API surfaces", target, 0, min(len(queue), max_candidates))

        connector = aiohttp.TCPConnector(ssl=False)
        findings: List[Dict[str, Any]] = []
        api_endpoints: List[Dict[str, Any]] = []
        checked: Set[str] = set()
        spec_documents: List[Dict[str, Any]] = []
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=90, connect=8, sock_read=15),
        ) as session:
            cursor = 0
            while cursor < len(queue) and len(checked) < max_candidates:
                path = queue[cursor]
                cursor += 1
                url = path if str(path).startswith("http") else urljoin(base, str(path))
                if url in checked:
                    continue
                checked.add(url)
                try:
                    fetched = await fetch_text(session, url, headers=parse_headers(parameters), max_bytes=1_500_000)
                    text = fetched.get("text") or ""
                    status = fetched.get("status")
                    content_type = fetched.get("headers", {}).get("content-type", "")
                    signal = self._classify_api_signal(url, status, content_type, text)
                    documents = _load_api_documents(text)
                    if documents and not signal:
                        signal = {"url": url, "status": status, "type": "openapi", "contentType": content_type}
                    if signal:
                        endpoints: List[Dict[str, Any]] = []
                        for document in documents:
                            document_endpoints = parse_openapi_endpoints(
                                document,
                                target=target,
                                spec_url=url,
                                include_cross_origin_servers=include_cross_origin,
                                max_endpoints=max_endpoints,
                            )
                            if document_endpoints:
                                spec_documents.append(
                                    {
                                        "url": url,
                                        "version": document.get("openapi") or document.get("swagger"),
                                        "title": ((document.get("info") or {}).get("title") if isinstance(document.get("info"), dict) else None),
                                        "endpoints": len(document_endpoints),
                                    }
                                )
                                endpoints.extend(document_endpoints)
                                api_endpoints.extend(document_endpoints)
                        if not endpoints and "swagger" in (text[:80_000].lower()):
                            refs = _extract_spec_refs_from_html(text[:120_000], fetched.get("url") or url)
                            for ref in refs:
                                if len(queue) >= max_candidates + 40:
                                    break
                                if ref not in checked:
                                    queue.append(ref)
                            if refs:
                                signal["specReferences"] = refs[:10]
                        signal["endpointCount"] = len(endpoints)
                        signal["documentKind"] = "spec" if endpoints else "ui_or_root"
                        findings.append(signal)
                    if agent:
                        agent.report_progress("Discovering API surfaces", url, len(checked), max_candidates)
                except Exception:
                    continue

        api_endpoints = _dedupe_endpoints(api_endpoints, max_endpoints)
        parameterized_urls = [
            endpoint["url"]
            for endpoint in api_endpoints
            if endpoint.get("method") in READONLY_METHODS and urlparse(str(endpoint.get("url"))).query
        ]
        method_counts = self._method_counts(api_endpoints)
        result = {
            "success": True,
            "target": target,
            "apiSurfaces": findings,
            "apiEndpoints": api_endpoints,
            "parameterizedUrls": _dedupe_keep_order(parameterized_urls, 300),
            "openapi": [f for f in findings if f["type"] == "openapi"],
            "openapiSpecs": spec_documents,
            "graphql": [f for f in findings if f["type"] == "graphql"],
            "apiRoots": [f for f in findings if f["type"] == "api_root"],
            "summary": {
                "candidatesChecked": len(checked),
                "apiSurfaces": len(findings),
                "openapi": sum(1 for f in findings if f["type"] == "openapi"),
                "openapiSpecsParsed": len(spec_documents),
                "graphql": sum(1 for f in findings if f["type"] == "graphql"),
                "apiEndpoints": len(api_endpoints),
                "readOnlyEndpoints": sum(1 for e in api_endpoints if e.get("method") in READONLY_METHODS),
                "writeEndpoints": sum(1 for e in api_endpoints if e.get("method") not in READONLY_METHODS),
                "templatedEndpoints": sum(1 for e in api_endpoints if e.get("pathParameters")),
                "parameterizedUrls": len(parameterized_urls),
                "methods": method_counts,
            },
            "recommendations": self._recommendations(api_endpoints, findings),
        }
        if agent:
            sample = ", ".join(f"{e.get('method')} {e.get('originalPath') or e.get('path')}" for e in api_endpoints[:5])
            agent.append_output(
                f"[api:discover] checked={len(checked)} surfaces={len(findings)} openapi={result['summary']['openapi']} "
                f"specsParsed={len(spec_documents)} endpoints={len(api_endpoints)}"
                + (f" sample=[{sample}]" if sample else "")
            )
        return result

    def _dedupe_paths(self, paths: Iterable[str]) -> List[str]:
        seen = set()
        output = []
        for path in paths:
            if not path:
                continue
            path = str(path)
            key = path if path.startswith("http") else "/" + path.lstrip("/")
            if key not in seen:
                seen.add(key)
                output.append(key)
        return output

    def _classify_api_signal(self, url: str, status: int, content_type: str, text: str):
        if status is None or status >= 500:
            return None
        lower = text[:5000].lower()
        if "openapi" in lower or "swagger" in lower or ('"paths"' in lower and '"info"' in lower):
            return {"url": url, "status": status, "type": "openapi", "contentType": content_type}
        if "graphql" in lower or url.rstrip("/").endswith(("graphql", "graphiql")):
            return {"url": url, "status": status, "type": "graphql", "contentType": content_type}
        if status in (200, 401, 403) and ("/api" in urlparse(url).path or "application/json" in content_type):
            return {"url": url, "status": status, "type": "api_root", "contentType": content_type}
        return None

    def _method_counts(self, endpoints: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for endpoint in endpoints:
            method = str(endpoint.get("method") or "GET").upper()
            counts[method] = counts.get(method, 0) + 1
        return counts

    def _recommendations(self, endpoints: List[Dict[str, Any]], surfaces: List[Dict[str, Any]]) -> List[str]:
        recommendations: List[str] = []
        if endpoints:
            recommendations.append("Feed apiEndpoints into api:access_control_probe for read-only anonymous/authenticated access checks.")
            if any(e.get("pathParameters") for e in endpoints):
                recommendations.append("Prioritize endpoints with path parameters for IDOR/BOLA mutation probes.")
            if any(e.get("requestBodyKeys") and e.get("method") not in READONLY_METHODS for e in endpoints):
                recommendations.append("In lab/aggressive mode, use OpenAPI requestBodyKeys as controlled POST/PUT form candidates.")
        elif surfaces:
            recommendations.append("API documentation UI was found, but no machine-readable OpenAPI document was parsed.")
        return recommendations


def get_tool():
    return ApiDiscoverTool()

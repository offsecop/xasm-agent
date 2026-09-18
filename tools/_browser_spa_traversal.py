"""Bounded, read-oriented traversal for browser reconnaissance tools.

The browser map and traffic-capture tools share this explorer so they observe
the same deterministic SPA states.  It deliberately supports only navigation
surfaces (same-origin links/router links), tabs/menu controls, and search input
events.  It never submits a form or clicks an unclassified generic button.

The caller owns the exact-origin Playwright context.  This module preserves
that boundary, validates authentication after every replayed interaction, and
returns explicit coverage metadata whenever a configured bound is reached.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import json
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse, urlunparse

from tools._agentic_exploration_common import RISKY_CLICK_WORDS, same_origin
from tools._browser_scoped_context import (
    BrowserCoverageIncomplete,
    ScopedBrowserContext,
    validate_authenticated_navigation,
)


DEFAULT_MAX_PAGES = 12
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_OUTPUT_BYTES = 48 * 1024
HARD_MAX_OUTPUT_BYTES = 64 * 1024
_MIN_OUTPUT_BYTES = 8 * 1024
_MAX_INTERSTITIAL_ACKNOWLEDGEMENTS = 3
_MAX_INTERACTION_DIAGNOSTICS = 40

_EXTRA_RISKY_WORDS = {
    "delete",
    "destroy",
    "disable",
    "deactivate",
    "unsubscribe",
    "close account",
    "reset",
    "revoke",
    "transfer",
    "checkout",
    "place order",
    "create",
    "invite",
    "upload",
}
_RISKY_WORDS = tuple(sorted(RISKY_CLICK_WORDS | _EXTRA_RISKY_WORDS))
_SAFE_SCHEMES = {"http", "https"}


class SpaTraversalIncomplete(BrowserCoverageIncomplete):
    """Typed INCOMPLETE result carrying already-observed, bounded evidence."""

    def __init__(self, reason: str, detail: str, partial: Dict[str, Any]):
        super().__init__(reason, detail)
        self.partial = partial


@dataclass(frozen=True)
class SpaTraversalBudget:
    max_pages: int
    max_depth: int
    max_interactions: int
    deadline_seconds: float
    max_output_bytes: int


@dataclass(frozen=True)
class _Action:
    signature: str
    kind: str
    label: str
    href: str


@dataclass(frozen=True)
class _ActionExecution:
    extra_interactions: int = 0
    diagnostic: Optional[Dict[str, Any]] = None


class _SafeInteractionBlocked(RuntimeError):
    """A classified browser control stayed unreachable without unsafe clicking."""

    def __init__(
        self,
        detail: str,
        diagnostic: Dict[str, Any],
        *,
        extra_interactions: int = 0,
    ):
        super().__init__(detail)
        self.diagnostic = diagnostic
        self.extra_interactions = extra_interactions


@dataclass(frozen=True)
class _QueuedState:
    path: Tuple[_Action, ...]
    depth: int


@dataclass
class _TraversalState:
    pages_observed: int = 0
    interactions_used: int = 0
    interaction_failures: int = 0
    candidates_observed: int = 0
    omitted_states: int = 0
    omitted_artifacts: int = 0
    blockers_observed: int = 0
    blockers_acknowledged: int = 0
    navigation_fallbacks: int = 0
    truncated_by: List[str] = field(default_factory=list)


def spa_traversal_budget(
    parameters: Dict[str, Any],
    *,
    default_interactions: int,
    default_timeout_seconds: int,
) -> SpaTraversalBudget:
    """Clamp caller-provided traversal bounds to conservative hard limits."""

    def integer(name: str, default: int) -> int:
        raw = parameters.get(name)
        return default if raw is None else int(raw)

    return SpaTraversalBudget(
        max_pages=max(1, min(integer("maxPages", DEFAULT_MAX_PAGES), 40)),
        max_depth=max(0, min(integer("maxDepth", DEFAULT_MAX_DEPTH), 6)),
        max_interactions=max(
            0,
            min(integer("maxInteractions", default_interactions), 60),
        ),
        deadline_seconds=float(
            max(5, min(integer("timeoutSeconds", default_timeout_seconds), 180))
        ),
        max_output_bytes=max(
            _MIN_OUTPUT_BYTES,
            min(
                integer("maxOutputBytes", DEFAULT_MAX_OUTPUT_BYTES),
                HARD_MAX_OUTPUT_BYTES,
            ),
        ),
    )


async def traverse_bounded_spa(
    page: Any,
    scoped: ScopedBrowserContext,
    target: str,
    budget: SpaTraversalBudget,
    *,
    root_navigation: Any = None,
    safe_interact: bool = True,
    fill_search_inputs: bool = False,
    search_term: str = "test",
) -> Dict[str, Any]:
    """Traverse deterministic same-origin SPA states within explicit bounds.

    Every queued state is reconstructed from the root using a short action
    path.  Re-querying controls during replay avoids stale element handles when
    React/Angular/Vue replace the DOM.  The actual clicks/fills (including
    replay) consume the interaction budget.
    """

    started = time.monotonic()
    deadline = started + budget.deadline_seconds
    queue: List[_QueuedState] = [_QueuedState(path=(), depth=0)]
    seen_states: set[str] = set()
    queued_paths: set[Tuple[str, ...]] = {()}
    state = _TraversalState()
    aggregates = _new_aggregates()
    first_state = True

    while queue:
        if time.monotonic() >= deadline:
            partial = _finish_result(aggregates, state, budget, target, started)
            partial.update(
                {
                    "coverageStatus": "INCOMPLETE",
                    "coverageReason": "SPA_TRAVERSAL_DEADLINE_EXCEEDED",
                    "exhaustiveWithinBounds": False,
                }
            )
            raise SpaTraversalIncomplete(
                "SPA_TRAVERSAL_DEADLINE_EXCEEDED",
                "bounded SPA traversal reached its deadline before the state queue was exhausted",
                partial,
            )
        if state.pages_observed >= budget.max_pages:
            _mark_truncated(state, "maxPages")
            state.omitted_states += len(queue)
            break

        node = queue.pop(0)
        required_clicks = len(node.path)
        if required_clicks and state.interactions_used + required_clicks > budget.max_interactions:
            _mark_truncated(state, "maxInteractions")
            state.omitted_states += 1 + len(queue)
            break

        try:
            if first_state:
                first_state = False
                navigation = root_navigation
            else:
                navigation = await _goto_root(page, target, deadline)

            await validate_authenticated_navigation(scoped, page, navigation, target)
            if not same_origin(target, str(page.url)):
                raise BrowserCoverageIncomplete(
                    "CROSS_ORIGIN_REDIRECT_BLOCKED",
                    "SPA traversal left the authorized primary origin",
                )

            for action in node.path:
                if time.monotonic() >= deadline:
                    partial = _finish_result(aggregates, state, budget, target, started)
                    partial.update(
                        {
                            "coverageStatus": "INCOMPLETE",
                            "coverageReason": "SPA_TRAVERSAL_DEADLINE_EXCEEDED",
                            "exhaustiveWithinBounds": False,
                        }
                    )
                    raise SpaTraversalIncomplete(
                        "SPA_TRAVERSAL_DEADLINE_EXCEEDED",
                        "bounded SPA traversal reached its deadline while replaying a state",
                        partial,
                    )
                snapshot = await _snapshot(page, target, fill_search_inputs)
                current = _find_action(snapshot.get("candidates", []), action.signature)
                if current is None:
                    raise RuntimeError("safe SPA control disappeared during deterministic replay")
                # Every attempted browser mutation consumes the bound, even if
                # Playwright later reports a detached element or timeout.
                state.interactions_used += 1
                try:
                    execution = await _perform_action(
                        page,
                        scoped,
                        target,
                        current,
                        search_term,
                        deadline,
                        allow_acknowledgement=(
                            state.interactions_used < budget.max_interactions
                            and state.blockers_acknowledged
                            < _MAX_INTERSTITIAL_ACKNOWLEDGEMENTS
                        ),
                    )
                except _SafeInteractionBlocked as exc:
                    state.interactions_used += exc.extra_interactions
                    if exc.diagnostic.get("blockerKind"):
                        state.blockers_observed += 1
                    if exc.diagnostic.get("acknowledged"):
                        state.blockers_acknowledged += 1
                    _record_interaction_diagnostic(
                        aggregates,
                        exc.diagnostic,
                        state,
                        budget,
                    )
                    raise
                state.interactions_used += execution.extra_interactions
                if execution.diagnostic:
                    state.blockers_observed += 1
                    if execution.diagnostic.get("acknowledged"):
                        state.blockers_acknowledged += 1
                    if execution.diagnostic.get("resolution") == "same-origin-goto":
                        state.navigation_fallbacks += 1
                    _record_interaction_diagnostic(
                        aggregates,
                        execution.diagnostic,
                        state,
                        budget,
                    )

            snapshot = await _snapshot(page, target, fill_search_inputs)
            await validate_authenticated_navigation(scoped, page, None, target)
        except SpaTraversalIncomplete:
            raise
        except BrowserCoverageIncomplete as exc:
            partial = _finish_result(aggregates, state, budget, target, started)
            partial.update(
                {
                    "coverageStatus": "INCOMPLETE",
                    "coverageReason": exc.reason,
                    "exhaustiveWithinBounds": False,
                }
            )
            raise SpaTraversalIncomplete(exc.reason, exc.detail, partial) from exc
        except Exception:
            state.interaction_failures += 1
            continue

        state_key = _state_key(snapshot)
        if state_key in seen_states:
            continue
        seen_states.add(state_key)
        state.pages_observed += 1
        _aggregate_snapshot(aggregates, snapshot, node, state, budget, target, scoped)

        candidates = _safe_candidates(
            snapshot.get("candidates", []),
            target,
            fill_search_inputs=fill_search_inputs,
        )
        state.candidates_observed += len(candidates)
        if not safe_interact:
            if candidates:
                state.omitted_states += len(candidates)
                _mark_truncated(state, "safeInteractDisabled")
            continue

        if node.depth >= budget.max_depth:
            if candidates:
                state.omitted_states += len(candidates)
                _mark_truncated(state, "maxDepth")
            continue

        for candidate in candidates:
            next_path = node.path + (_action_from_candidate(candidate),)
            path_signature = tuple(action.signature for action in next_path)
            if path_signature in queued_paths:
                continue
            queued_paths.add(path_signature)
            queue.append(_QueuedState(path=next_path, depth=node.depth + 1))

    result = _finish_result(aggregates, state, budget, target, started)
    if (
        state.candidates_observed > 0
        and state.pages_observed <= 1
        and state.interaction_failures > 0
        and not state.truncated_by
    ):
        result["coverageStatus"] = "INCOMPLETE"
        result["coverageReason"] = "SAFE_SPA_INTERACTIONS_UNREACHABLE"
        result["exhaustiveWithinBounds"] = False
    return result


async def _goto_root(page: Any, target: str, deadline: float) -> Any:
    remaining_ms = max(250, int((deadline - time.monotonic()) * 1000))
    return await page.goto(
        target,
        wait_until="domcontentloaded",
        timeout=min(remaining_ms, 15_000),
    )


async def _perform_action(
    page: Any,
    scoped: ScopedBrowserContext,
    target: str,
    candidate: Dict[str, Any],
    search_term: str,
    deadline: float,
    *,
    allow_acknowledgement: bool,
) -> _ActionExecution:
    selector = f'[data-xasm-spa-key="{candidate["key"]}"]'
    locator = page.locator(selector).first
    blocked_before = len(scoped.blocked_navigation_urls)
    remaining_ms = max(250, int((deadline - time.monotonic()) * 1000))
    action_timeout = min(remaining_ms, 2_000)
    navigation_timeout = min(remaining_ms, 5_000)
    inspection = await _inspect_actionability(page, selector)
    diagnostic: Optional[Dict[str, Any]] = None
    extra_interactions = 0

    if inspection.get("state") != "actionable":
        diagnostic = _actionability_diagnostic(candidate, inspection)
        recognized_blocker = bool(inspection.get("blockerKind"))
        ack_key = str(inspection.get("ackKey") or "")
        if recognized_blocker and ack_key and allow_acknowledgement:
            ack_locator = page.locator(
                f'[data-xasm-interstitial-key="{ack_key}"]'
            ).first
            extra_interactions = 1
            try:
                await ack_locator.click(timeout=action_timeout, no_wait_after=True)
                diagnostic["acknowledged"] = True
                await page.wait_for_timeout(min(350, max(100, action_timeout // 5)))
                await _validate_action_scope(
                    page,
                    scoped,
                    target,
                    None,
                    blocked_before,
                )
                inspection = await _inspect_actionability(page, selector)
            except BrowserCoverageIncomplete:
                raise
            except Exception:
                diagnostic["acknowledgementFailed"] = True
                await _validate_action_scope(
                    page,
                    scoped,
                    target,
                    None,
                    blocked_before,
                )

        if inspection.get("state") != "actionable":
            if recognized_blocker and _safe_navigation_fallback(candidate, scoped):
                try:
                    navigation = await _goto_primary_fallback(
                        page,
                        scoped,
                        str(candidate.get("href") or ""),
                        navigation_timeout,
                        blocked_before,
                    )
                except Exception:
                    await _validate_action_scope(
                        page,
                        scoped,
                        target,
                        None,
                        blocked_before,
                    )
                    raise
                await _validate_action_scope(
                    page,
                    scoped,
                    target,
                    navigation,
                    blocked_before,
                )
                diagnostic["resolution"] = "same-origin-goto"
                return _ActionExecution(
                    extra_interactions=extra_interactions,
                    diagnostic=diagnostic,
                )
            diagnostic["resolution"] = (
                "acknowledgement-cap-reached"
                if recognized_blocker and ack_key and not allow_acknowledgement
                else "blocked"
            )
            raise _SafeInteractionBlocked(
                "safe SPA control is covered by an unacknowledged or unclassified interstitial",
                diagnostic,
                extra_interactions=extra_interactions,
            )

    if candidate.get("kind") == "search":
        # Filling dispatches input/change events but never submits the form.
        await locator.fill(str(search_term or "test")[:80], timeout=action_timeout)
    else:
        await locator.click(timeout=action_timeout, no_wait_after=True)
    await page.wait_for_timeout(min(500, max(100, action_timeout // 4)))
    try:
        await page.wait_for_load_state("networkidle", timeout=min(action_timeout, 1_500))
    except Exception:
        pass
    await _validate_action_scope(
        page,
        scoped,
        target,
        None,
        blocked_before,
    )
    if diagnostic is not None:
        diagnostic["resolution"] = "acknowledged"
    return _ActionExecution(
        extra_interactions=extra_interactions,
        diagnostic=diagnostic,
    )


async def _goto_primary_fallback(
    page: Any,
    scoped: ScopedBrowserContext,
    href: str,
    timeout_ms: int,
    blocked_before: int,
) -> Any:
    """Navigate a proved primary href without following a document redirect out."""

    session = None
    paused_tasks: List[asyncio.Task[Any]] = []

    async def keep_fallback_document_primary(event: Dict[str, Any]) -> None:
        request = event.get("request") or {}
        request_url = str(request.get("url") or "")
        resource_type = str(event.get("resourceType") or "").lower()
        request_id = str(event.get("requestId") or "")
        if resource_type == "document" and not scoped.url_is_primary(request_url):
            scoped.note_blocked_url(
                request_url,
                navigation=True,
                reason="CROSS_ORIGIN_REDIRECT_BLOCKED",
            )
            await session.send(
                "Fetch.failRequest",
                {"requestId": request_id, "errorReason": "BlockedByClient"},
            )
            return
        # Continue without rewriting headers, cookies, or the request URL. The
        # existing context policy remains responsible for subresource scope and
        # cross-origin authentication-header stripping.
        await session.send("Fetch.continueRequest", {"requestId": request_id})

    try:
        session = await page.context.new_cdp_session(page)
        session.on(
            "Fetch.requestPaused",
            lambda event: paused_tasks.append(
                asyncio.create_task(keep_fallback_document_primary(event))
            ),
        )
        await session.send(
            "Fetch.enable",
            {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
        )
        return await page.goto(
            href,
            wait_until="domcontentloaded",
            timeout=timeout_ms,
        )
    except BrowserCoverageIncomplete:
        raise
    except Exception:
        if paused_tasks:
            await asyncio.gather(*paused_tasks, return_exceptions=True)
        if len(scoped.blocked_navigation_urls) > blocked_before:
            raise BrowserCoverageIncomplete(
                "CROSS_ORIGIN_REDIRECT_BLOCKED",
                "safe SPA navigation fallback attempted to leave the primary origin",
            )
        raise
    finally:
        if paused_tasks:
            await asyncio.gather(*paused_tasks, return_exceptions=True)
        if session is not None:
            try:
                await session.send("Fetch.disable")
            except Exception:
                pass
            try:
                await session.detach()
            except Exception:
                pass


async def _validate_action_scope(
    page: Any,
    scoped: ScopedBrowserContext,
    target: str,
    navigation: Any,
    blocked_before: int,
) -> None:
    if len(scoped.blocked_navigation_urls) > blocked_before:
        raise BrowserCoverageIncomplete(
            "CROSS_ORIGIN_REDIRECT_BLOCKED",
            "safe SPA interaction attempted to navigate outside the authorized origin",
        )
    if not same_origin(target, str(page.url)):
        raise BrowserCoverageIncomplete(
            "CROSS_ORIGIN_REDIRECT_BLOCKED",
            "safe SPA interaction left the authorized primary origin",
        )
    await validate_authenticated_navigation(scoped, page, navigation, target)


def _safe_navigation_fallback(
    candidate: Dict[str, Any],
    scoped: ScopedBrowserContext,
) -> bool:
    href = str(candidate.get("href") or "").strip()
    parsed = urlparse(href)
    return bool(
        candidate.get("kind") == "navigate"
        and str(candidate.get("navigationSource") or "")
        in {"anchor-href", "router-href"}
        and parsed.scheme.lower() in _SAFE_SCHEMES
        and scoped.url_is_primary(href)
    )


def _actionability_diagnostic(
    candidate: Dict[str, Any],
    inspection: Dict[str, Any],
) -> Dict[str, Any]:
    signature = str(candidate.get("signature") or "")
    diagnostic: Dict[str, Any] = {
        "actionId": hashlib.sha256(signature.encode("utf-8")).hexdigest()[:12],
        "kind": str(candidate.get("kind") or "")[:24],
        "actionability": str(inspection.get("state") or "unknown")[:40],
        "resolution": "pending",
    }
    blocker_kind = str(inspection.get("blockerKind") or "")[:24]
    ack_label = str(inspection.get("ackLabel") or "")[:32]
    if blocker_kind:
        diagnostic["blockerKind"] = blocker_kind
    if ack_label:
        # The browser-side classifier returns only a canonical allowlist token,
        # never arbitrary DOM text.
        diagnostic["ackControl"] = ack_label
    return diagnostic


async def _inspect_actionability(page: Any, selector: str) -> Dict[str, Any]:
    """Return a bounded classification without exposing page text or selectors."""

    result = await page.evaluate(
        """({ selector }) => {
          const target = document.querySelector(selector);
          const visible = (el) => {
            if (!el || !el.isConnected) return false;
            const style = getComputedStyle(el);
            const rect = el.getBoundingClientRect();
            return style.display !== 'none' && style.visibility !== 'hidden' &&
              style.pointerEvents !== 'none' && Number(style.opacity || 1) > 0 &&
              rect.width > 0 && rect.height > 0;
          };
          if (!target) return { state: 'missing' };
          if (!visible(target)) return { state: 'not-visible' };
          const rect = target.getBoundingClientRect();
          const x = Math.max(0, Math.min(innerWidth - 1, rect.left + rect.width / 2));
          const y = Math.max(0, Math.min(innerHeight - 1, rect.top + rect.height / 2));
          const hit = document.elementFromPoint(x, y);
          if (hit && (hit === target || target.contains(hit))) {
            return { state: 'actionable' };
          }

          const normalize = (value, max = 1200) => String(value || '')
            .normalize('NFKD').replace(/[\u0300-\u036f]/g, '')
            .toLowerCase().replace(/\\s+/g, ' ').trim().slice(0, max);
          const category = (el) => {
            const heading = el.querySelector('h1, h2, h3, [role=heading]');
            const text = normalize(`${el.getAttribute('aria-label') || ''} ${heading ? heading.textContent : ''} ${el.textContent || ''}`);
            if (/\\b(cookie|cookies|consent|privacy|privacidade|preferencias de cookies|preferencias de privacidad)\\b/.test(text)) return 'consent';
            if (/\\b(disclosure|disclaimer|important notice|security notice|aviso importante|termos e condicoes|terms and conditions)\\b/.test(text)) return 'disclosure';
            return '';
          };
          const candidates = [];
          let current = hit;
          while (current && current !== document.documentElement) {
            candidates.push(current);
            current = current.parentElement;
          }
          document.querySelectorAll('[role=dialog], [role=alertdialog], [aria-modal=true], dialog[open]').forEach(el => candidates.push(el));
          const unique = Array.from(new Set(candidates));
          const blocker = unique.find((el) => {
            if (!visible(el) || !category(el)) return false;
            const blockerRect = el.getBoundingClientRect();
            const coversPoint = x >= blockerRect.left && x <= blockerRect.right &&
              y >= blockerRect.top && y <= blockerRect.bottom;
            const role = normalize(el.getAttribute('role'), 40);
            const style = getComputedStyle(el);
            const zIndex = Number.parseInt(style.zIndex || '0', 10) || 0;
            const positionedOverlay = style.position === 'fixed' ||
              style.position === 'sticky' ||
              (style.position === 'absolute' && zIndex > 0);
            const modal = el.getAttribute('aria-modal') === 'true' ||
              role === 'dialog' || role === 'alertdialog' ||
              (el.tagName.toLowerCase() === 'dialog' && el.hasAttribute('open'));
            if (!positionedOverlay && !modal) return false;
            return coversPoint || (modal && hit && el.contains(hit));
          });
          if (!blocker) return { state: 'covered-unclassified' };

          document.querySelectorAll('[data-xasm-interstitial-key]').forEach(el =>
            el.removeAttribute('data-xasm-interstitial-key'));
          const allow = [
            [/^(accept|accept all|allow all)( cookies)?$/, 'accept'],
            [/^(aceitar|aceitar tudo|permitir tudo)( cookies)?$/, 'accept'],
            [/^(agree|i agree|concordo)$/, 'agree'],
            [/^(continue|continuar|prosseguir)$/, 'continue'],
            [/^(acknowledge|i understand|got it|entendi)$/, 'acknowledge'],
            [/^(ok|okay)$/, 'ok'],
            [/^(close|dismiss|fechar)$/, 'close'],
          ];
          let ackKey = '';
          let ackLabel = '';
          const controls = blocker.querySelectorAll('button, input[type=button], [role=button]');
          for (const control of controls) {
            if (!visible(control) || control.disabled || control.getAttribute('aria-disabled') === 'true') continue;
            if (control.closest('form') || control.hasAttribute('form') || control.hasAttribute('formaction')) continue;
            if (control.hasAttribute('href')) continue;
            const type = normalize(control.getAttribute('type'), 20);
            if (type && type !== 'button') continue;
            const label = normalize(control.getAttribute('aria-label') || control.value || control.textContent, 80);
            const matched = allow.find(([pattern]) => pattern.test(label));
            if (!matched) continue;
            ackKey = 'ack0';
            ackLabel = matched[1];
            control.setAttribute('data-xasm-interstitial-key', ackKey);
            break;
          }
          return {
            state: 'covered-by-safe-interstitial',
            blockerKind: category(blocker),
            ackKey,
            ackLabel,
          };
        }""",
        {"selector": selector},
    )
    if not isinstance(result, dict):
        return {"state": "unknown"}
    return {
        "state": str(result.get("state") or "unknown")[:40],
        "blockerKind": str(result.get("blockerKind") or "")[:24],
        "ackKey": str(result.get("ackKey") or "")[:32],
        "ackLabel": str(result.get("ackLabel") or "")[:32],
    }


async def _snapshot(page: Any, target: str, include_search: bool) -> Dict[str, Any]:
    snapshot = await page.evaluate(
        """({ includeSearch }) => {
          const clean = (value, max = 160) => String(value || '').trim().replace(/\\s+/g, ' ').slice(0, max);
          const absolute = (value) => {
            try { return new URL(value || location.href, location.href).href; } catch (_) { return ''; }
          };
          const fields = (form) => Array.from(form.querySelectorAll('input, textarea, select')).map(i => {
            const type = (i.getAttribute('type') || i.tagName || 'text').toLowerCase();
            return {
              name: clean(i.getAttribute('name') || i.id, 160),
              type,
              // Recon records the input contract, never a live value. Authenticated
              // pages routinely contain password, CSRF, session, account and PII
              // values whose sibling `type`/`name` metadata is not sufficient for
              // a generic key-based redactor to classify safely.
              hasValue: Boolean(i.value),
            };
          }).filter(i => i.name || ['password','email','search','file'].includes(i.type));
          const links = Array.from(document.querySelectorAll('a[href], [routerlink], [data-route]')).map(el => ({
            url: absolute(el.getAttribute('href') || el.getAttribute('routerlink') || el.getAttribute('data-route')),
            label: clean(el.innerText || el.textContent || el.getAttribute('aria-label')),
          })).filter(item => item.url).slice(0, 300);
          const forms = Array.from(document.forms).map(f => ({
            action: absolute(f.getAttribute('action') || location.href),
            method: (f.getAttribute('method') || 'GET').toUpperCase(),
            contentType: (f.getAttribute('enctype') || 'application/x-www-form-urlencoded').toLowerCase(),
            fields: fields(f),
          })).slice(0, 120);
          const buttons = Array.from(document.querySelectorAll('button, [role=button], [role=tab], [role=menuitem], input[type=button], input[type=submit], a')).map(el => ({
            label: clean(el.innerText || el.textContent || el.getAttribute('aria-label') || el.getAttribute('value')),
            tag: el.tagName.toLowerCase(),
            href: absolute(el.getAttribute('href') || el.getAttribute('routerlink') || el.getAttribute('data-route')),
            type: clean(el.getAttribute('type'), 40).toLowerCase(),
            role: clean(el.getAttribute('role'), 40).toLowerCase(),
            ariaControls: clean(el.getAttribute('aria-controls'), 120),
          })).filter(item => item.label || item.href).slice(0, 240);
          const inputs = Array.from(document.querySelectorAll('input, textarea, select')).map(i => ({
            name: clean(i.getAttribute('name') || i.id, 160),
            type: (i.getAttribute('type') || i.tagName || 'text').toLowerCase(),
          })).slice(0, 240);

          const rawCandidates = Array.from(document.querySelectorAll(
            'a[href], [routerlink], [data-route], [role=tab], [role=menuitem], button[aria-controls], [role=button][aria-controls]' +
            (includeSearch ? ', input[type=search], input[name*=search i], input[id*=search i], input[placeholder*=search i]' : '')
          ));
          const candidates = [];
          rawCandidates.forEach((el, index) => {
            const tag = el.tagName.toLowerCase();
            const role = clean(el.getAttribute('role'), 40).toLowerCase();
            const anchorHref = tag === 'a' ? (el.getAttribute('href') || '') : '';
            const routerHref = el.getAttribute('routerlink') || '';
            const hrefRaw = anchorHref || routerHref || el.getAttribute('data-route') || '';
            const href = hrefRaw ? absolute(hrefRaw) : '';
            const navigationSource = anchorHref ? 'anchor-href' : (routerHref ? 'router-href' : '');
            const label = clean(el.innerText || el.textContent || el.getAttribute('aria-label') || el.getAttribute('placeholder') || el.getAttribute('name'));
            const ariaControls = clean(el.getAttribute('aria-controls'), 120);
            const type = clean(el.getAttribute('type'), 40).toLowerCase();
            const search = tag === 'input' && (type === 'search' || /search/i.test(`${el.name || ''} ${el.id || ''} ${el.placeholder || ''}`));
            if (!search && !href && !['tab', 'menuitem'].includes(role) && !ariaControls) return;
            if (role === 'menuitem' && !href && !ariaControls) return;
            if (el.closest('form') && !search && tag !== 'a') return;
            if (tag === 'button' && type === 'submit') return;
            const kind = search ? 'search' : (href ? 'navigate' : 'toggle');
            const signature = JSON.stringify([kind, tag, role, href, navigationSource, ariaControls, label]);
            const key = `c${index}`;
            el.setAttribute('data-xasm-spa-key', key);
            candidates.push({ key, signature, kind, tag, role, href, navigationSource, ariaControls, label });
          });
          return {
            title: document.title || '',
            url: location.href,
            links,
            scripts: Array.from(document.querySelectorAll('script[src]')).map(s => absolute(s.getAttribute('src'))).filter(Boolean).slice(0, 300),
            forms,
            buttons,
            inputs,
            candidates: candidates.slice(0, 300),
          };
        }""",
        {"includeSearch": bool(include_search)},
    )
    route_url = str(snapshot.get("url") or page.url)
    if not same_origin(target, route_url):
        raise BrowserCoverageIncomplete(
            "CROSS_ORIGIN_REDIRECT_BLOCKED",
            "SPA snapshot left the authorized primary origin",
        )
    return snapshot


def _safe_candidates(
    raw_candidates: Iterable[Dict[str, Any]],
    target: str,
    *,
    fill_search_inputs: bool,
) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in raw_candidates:
        if not isinstance(candidate, dict):
            continue
        signature = str(candidate.get("signature") or "")
        kind = str(candidate.get("kind") or "")
        label = str(candidate.get("label") or "").strip()
        href = str(candidate.get("href") or "").strip()
        if not signature or signature in seen:
            continue
        lowered = f"{label} {href}".lower()
        if any(word in lowered for word in _RISKY_WORDS):
            continue
        if kind == "search" and not fill_search_inputs:
            continue
        if kind == "navigate":
            parsed = urlparse(href)
            if parsed.scheme.lower() not in _SAFE_SCHEMES or not same_origin(target, href):
                continue
        if kind not in {"navigate", "toggle", "search"}:
            continue
        seen.add(signature)
        output.append(candidate)
    return output


def _action_from_candidate(candidate: Dict[str, Any]) -> _Action:
    return _Action(
        signature=str(candidate.get("signature") or ""),
        kind=str(candidate.get("kind") or ""),
        label=str(candidate.get("label") or "")[:120],
        href=str(candidate.get("href") or ""),
    )


def _find_action(candidates: Sequence[Dict[str, Any]], signature: str) -> Optional[Dict[str, Any]]:
    return next(
        (
            candidate
            for candidate in candidates
            if isinstance(candidate, dict) and str(candidate.get("signature") or "") == signature
        ),
        None,
    )


def _state_key(snapshot: Dict[str, Any]) -> str:
    shape = {
        "url": _normalize_state_url(str(snapshot.get("url") or "")),
        "forms": [
            {
                "action": form.get("action"),
                "method": form.get("method"),
                "fields": [
                    (field.get("name"), field.get("type"))
                    for field in list(form.get("fields") or [])
                    if isinstance(field, dict)
                ],
            }
            for form in list(snapshot.get("forms") or [])
            if isinstance(form, dict)
        ],
        "inputs": [
            (item.get("name"), item.get("type"))
            for item in list(snapshot.get("inputs") or [])
            if isinstance(item, dict)
        ],
        "controls": [
            str(item.get("signature") or "")
            for item in list(snapshot.get("candidates") or [])
            if isinstance(item, dict)
        ],
    }
    canonical = json.dumps(shape, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _normalize_state_url(value: str) -> str:
    parsed = urlparse(value)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, parsed.fragment))


def _new_aggregates() -> Dict[str, Any]:
    return {
        "visitedStates": [],
        "links": [],
        "linkObservations": [],
        "externalLinks": [],
        "scripts": [],
        "scriptObservations": [],
        "forms": [],
        "buttons": [],
        "inputs": [],
        "safeInteractions": [],
        "interactionDiagnostics": [],
        "_seen": {
            "links": set(),
            "externalLinks": set(),
            "scripts": set(),
            "forms": set(),
            "buttons": set(),
            "inputs": set(),
        },
        "_artifactBytes": 0,
    }


def _aggregate_snapshot(
    aggregates: Dict[str, Any],
    snapshot: Dict[str, Any],
    node: _QueuedState,
    state: _TraversalState,
    budget: SpaTraversalBudget,
    target: str,
    scoped: ScopedBrowserContext,
) -> None:
    route_url = str(snapshot.get("url") or "")
    state_id = _state_key(snapshot)
    state_row = {
        "stateId": state_id,
        "routeUrl": route_url,
        "depth": node.depth,
        "title": str(snapshot.get("title") or "")[:240],
        "linkCount": len(snapshot.get("links") or []),
        "formCount": len(snapshot.get("forms") or []),
        "inputCount": len(snapshot.get("inputs") or []),
        "safeCandidateCount": len(snapshot.get("candidates") or []),
    }
    _append_bounded(aggregates, "visitedStates", state_row, state, budget)

    for raw in snapshot.get("links") or []:
        if not isinstance(raw, dict):
            continue
        url = str(raw.get("url") or "")
        if not url:
            continue
        if scoped.url_is_primary(url):
            if url not in aggregates["_seen"]["links"]:
                aggregates["_seen"]["links"].add(url)
                _append_bounded(aggregates, "links", url, state, budget)
            _append_bounded(
                aggregates,
                "linkObservations",
                {"url": url, "routeUrl": route_url},
                state,
                budget,
            )
        elif scoped.url_is_authorized(url) and url not in aggregates["_seen"]["externalLinks"]:
            aggregates["_seen"]["externalLinks"].add(url)
            _append_bounded(aggregates, "externalLinks", url, state, budget)
        elif not scoped.url_is_authorized(url):
            scoped.note_blocked_url(url)

    for script in snapshot.get("scripts") or []:
        url = str(script or "")
        if not url or url in aggregates["_seen"]["scripts"]:
            continue
        if not scoped.url_is_authorized(url):
            scoped.note_blocked_url(url)
            continue
        aggregates["_seen"]["scripts"].add(url)
        _append_bounded(aggregates, "scripts", url, state, budget)
        _append_bounded(
            aggregates,
            "scriptObservations",
            {"url": url, "routeUrl": route_url},
            state,
            budget,
        )

    for form in snapshot.get("forms") or []:
        if not isinstance(form, dict):
            continue
        action = str(form.get("action") or "")
        if action and not scoped.url_is_authorized(action):
            scoped.note_blocked_url(action)
            continue
        row = {**form, "routeUrl": route_url}
        signature = json.dumps(
            [
                row.get("action"),
                row.get("method"),
                [
                    (field.get("name"), field.get("type"))
                    for field in list(row.get("fields") or [])
                    if isinstance(field, dict)
                ],
            ],
            sort_keys=True,
        )
        if signature in aggregates["_seen"]["forms"]:
            continue
        aggregates["_seen"]["forms"].add(signature)
        _append_bounded(aggregates, "forms", row, state, budget)

    for key in ("buttons", "inputs"):
        for item in snapshot.get(key) or []:
            if not isinstance(item, dict):
                continue
            row = {**item, "routeUrl": route_url}
            href = str(row.get("href") or "")
            if href and not scoped.url_is_authorized(href):
                scoped.note_blocked_url(href)
                row["href"] = ""
            signature = json.dumps(row, sort_keys=True, separators=(",", ":"))
            if signature in aggregates["_seen"][key]:
                continue
            aggregates["_seen"][key].add(signature)
            _append_bounded(aggregates, key, row, state, budget)

    if node.depth > 0:
        action = node.path[-1]
        _append_bounded(
            aggregates,
            "safeInteractions",
            {
                "afterUrl": route_url,
                "beforeUrl": target_url_from_path(node.path[:-1], target),
                "depth": node.depth,
                "label": action.label,
                "kind": action.kind,
                "openedModalOrForm": bool(snapshot.get("forms")),
                "formCountAfter": len(snapshot.get("forms") or []),
            },
            state,
            budget,
        )


def _append_bounded(
    aggregates: Dict[str, Any],
    key: str,
    item: Any,
    state: _TraversalState,
    budget: SpaTraversalBudget,
) -> bool:
    encoded_bytes = len(json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 2
    if aggregates["_artifactBytes"] + encoded_bytes > budget.max_output_bytes:
        state.omitted_artifacts += 1
        _mark_truncated(state, "maxOutputBytes")
        return False
    aggregates[key].append(item)
    aggregates["_artifactBytes"] += encoded_bytes
    return True


def _record_interaction_diagnostic(
    aggregates: Dict[str, Any],
    diagnostic: Dict[str, Any],
    state: _TraversalState,
    budget: SpaTraversalBudget,
) -> None:
    diagnostics = aggregates.get("interactionDiagnostics")
    if not isinstance(diagnostics, list):
        return
    if len(diagnostics) >= _MAX_INTERACTION_DIAGNOSTICS:
        state.omitted_artifacts += 1
        _mark_truncated(state, "maxInteractionDiagnostics")
        return
    _append_bounded(
        aggregates,
        "interactionDiagnostics",
        diagnostic,
        state,
        budget,
    )


def _mark_truncated(state: _TraversalState, reason: str) -> None:
    if reason not in state.truncated_by:
        state.truncated_by.append(reason)


def _finish_result(
    aggregates: Dict[str, Any],
    state: _TraversalState,
    budget: SpaTraversalBudget,
    target: str,
    started: float,
) -> Dict[str, Any]:
    public = {key: value for key, value in aggregates.items() if not key.startswith("_")}
    elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
    root_surface_count = (
        len(public["links"])
        + len(public["forms"])
        + len(public["buttons"])
        + len(public["inputs"])
    )
    truncated = bool(state.truncated_by)
    if truncated:
        coverage_status = "CONFIRMED" if state.pages_observed > 0 else "INCOMPLETE"
        coverage_reason = "BOUNDED_SPA_CAP_REACHED"
    elif root_surface_count == 0:
        coverage_status = "COMPLETE_NO_FINDING"
        coverage_reason = "ROOT_REACHABLE_NO_INTERACTIVE_SURFACE"
    else:
        coverage_status = "CONFIRMED"
        coverage_reason = "BOUNDED_SPA_TRAVERSAL_COMPLETED"

    public.update(
        {
            "coverageStatus": coverage_status,
            "coverageReason": coverage_reason,
            "exhaustiveWithinBounds": not truncated,
            "truncated": truncated,
            "truncatedBy": list(state.truncated_by),
            "omittedStates": state.omitted_states,
            "omittedArtifacts": state.omitted_artifacts,
            "pagesObserved": state.pages_observed,
            "interactionsUsed": state.interactions_used,
            "interactionFailures": state.interaction_failures,
            "candidatesObserved": state.candidates_observed,
            "blockersObserved": state.blockers_observed,
            "blockersAcknowledged": state.blockers_acknowledged,
            "navigationFallbacks": state.navigation_fallbacks,
            "elapsedMs": elapsed_ms,
            "artifactBytes": int(aggregates["_artifactBytes"]),
            "budget": {
                "maxPages": budget.max_pages,
                "maxDepth": budget.max_depth,
                "maxInteractions": budget.max_interactions,
                "deadlineSeconds": budget.deadline_seconds,
                "maxOutputBytes": budget.max_output_bytes,
            },
            "target": target,
        }
    )
    return public


def merge_incomplete_output(
    base: Dict[str, Any],
    failure: BrowserCoverageIncomplete,
) -> Dict[str, Any]:
    """Attach safe partial SPA artifacts to a typed INCOMPLETE tool result."""

    partial = failure.partial if isinstance(failure, SpaTraversalIncomplete) else {}
    if not isinstance(partial, dict):
        partial = {}
    return {
        **partial,
        **base,
        "success": False,
        "coverageStatus": "INCOMPLETE",
        "coverageReason": failure.reason,
        "exhaustiveWithinBounds": False,
        "error": failure.detail,
    }


def compact_json_bytes(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def target_url_from_path(path: Sequence[_Action], fallback: str) -> str:
    for action in reversed(path):
        if action.href:
            return action.href
    return fallback


def enforce_public_output_cap(
    output: Dict[str, Any],
    max_bytes: int,
    *,
    removable_lists: Sequence[str],
    private_keys: Sequence[str] = (),
) -> Dict[str, Any]:
    """Keep the LLM-visible result valid JSON and within its byte lane.

    Private transport envelopes are intentionally excluded: AgentEngine
    removes them before the result enters LLM context.  Public evidence is
    trimmed from caller-selected, lowest-priority arrays and the omission is
    reported instead of relying on the generic string sanitizer to cut JSON in
    the middle of an object.
    """

    cap = max(_MIN_OUTPUT_BYTES, min(int(max_bytes), HARD_MAX_OUTPUT_BYTES))
    # Reserve room for the coverage metadata this function adds after trimming.
    trim_cap = max(1024, cap - 512)

    def public_view() -> Dict[str, Any]:
        return {key: value for key, value in output.items() if key not in private_keys}

    omitted = 0
    # Samples are useful but lowest priority; preserve endpoint shape and
    # route provenance before dropping entire request observations.
    for row in reversed(list(output.get("xhrRequests") or [])):
        if compact_json_bytes(public_view()) <= trim_cap:
            break
        if not isinstance(row, dict):
            continue
        for key in ("responseSample", "requestSample"):
            if row.get(key):
                row[key] = "[omitted by browser output byte cap]"
                omitted += 1

    while compact_json_bytes(public_view()) > trim_cap:
        removed = False
        for key in removable_lists:
            values = output.get(key)
            if isinstance(values, list) and values:
                values.pop()
                omitted += 1
                removed = True
                break
        if not removed:
            break

    if omitted:
        coverage = output.setdefault("coverage", {})
        reasons = coverage.setdefault("truncatedBy", [])
        if "maxOutputBytes" not in reasons:
            reasons.append("maxOutputBytes")
        coverage["truncated"] = True
        coverage["exhaustiveWithinBounds"] = False
        coverage["omittedArtifacts"] = int(coverage.get("omittedArtifacts") or 0) + omitted
        output.setdefault("summary", {})["truncated"] = True
        output["summary"]["omittedArtifacts"] = coverage["omittedArtifacts"]
        if output.get("coverageStatus") != "INCOMPLETE":
            output["coverageStatus"] = "CONFIRMED"
            output["coverageReason"] = "BOUNDED_SPA_CAP_REACHED"
    coverage = output.setdefault("coverage", {})
    coverage["maxOutputBytes"] = cap
    coverage["publicOutputBytes"] = compact_json_bytes(public_view())
    # Recalculate once with the field itself present (digit-length drift is
    # bounded and this second pass is exact for normal output sizes).
    coverage["publicOutputBytes"] = compact_json_bytes(public_view())
    return output

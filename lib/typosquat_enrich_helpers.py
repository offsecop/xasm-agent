"""
Typosquat enrichment mixin.

Per-registered-domain enrichment shared by BOTH the discovery tool
(`typosquat:detect`, which enriches the registered subset it just discovered)
and the standalone enrichment tool (`typosquat:enrich`, which enriches
already-discovered lookalikes on a decoupled cadence — issue #1049).

The mixin owns ONLY the enrichment surface: HTTP/SSL, page title, MX,
VirusTotal/PhishTank/OpenPhish threat-feed lookups, email-auth (SPF/DMARC/DKIM),
and RDAP-primary → port-43-WHOIS registration-age capture, plus the in-process
rate-limiter state those calls share. Permutation/generation and risk-scoring
logic stay on `TyposquatDetectTool` (they are discovery-only, not shared).

Both tool classes inherit this mixin so `self._check_http`, `self._rdap_created`,
etc. resolve unchanged via the MRO. `__init__` here initializes the shared
limiter state; subclasses that need no extra state can rely on it directly.
"""

import asyncio
import html
import json
import logging
import os
import re
import ssl
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from lib.process_reaper import register_group, terminate_group  # noqa: E402
from lib.dns_async import resolve_records  # noqa: E402

# RDAP-primary domain-age capture. asyncwhois (v1.1.12, pure-python / ARM-safe —
# unlike the cryptography 48.x SIGILL case) wraps whodap RDAP with a port-43
# WHOIS fallback in one async client. RDAP exposes the registration date as a
# clean ISO `events[].eventAction=="registration".eventDate`, which sidesteps the
# port-43 first-match-`created:` artifact (e.g. the CIRA `.ca` 1987 banner line).
# Imported guardedly so the tool still loads if the dependency is briefly absent
# during a partial agent rebuild (a requirements bump needs rebuild+recreate of
# all 5 agents, not just a restart).
try:
    import asyncwhois  # noqa: E402
    from asyncwhois.parse import TLDBaseKeys as _AwKeys  # noqa: E402
except Exception:  # pragma: no cover - import-time resilience only
    asyncwhois = None
    _AwKeys = None

# A4 — TLS leaf-certificate parsing for lookalike-infrastructure correlation
# (issuer + SHA-256 fingerprint link domains run by the same operator). The
# repo pins `cryptography>=44,<45` on purpose (48.x aarch64 wheels SIGILL on
# this VM — see requirements.txt); do NOT bump that pin. Imported guardedly so
# the tool still loads during a partial agent rebuild — a missing dependency
# degrades to the bare has-cert signal (no parsed detail), never an ImportError.
try:
    from cryptography import x509 as _x509  # noqa: E402
    from cryptography.hazmat.primitives import hashes as _crypto_hashes  # noqa: E402
    from cryptography.x509.oid import (  # noqa: E402
        ExtensionOID as _ExtensionOID,
        NameOID as _NameOID,
    )
except Exception:  # pragma: no cover - import-time resilience only
    _x509 = None
    _crypto_hashes = None
    _ExtensionOID = None
    _NameOID = None

from lib.integration_credentials import (  # noqa: E402
    checkout_provider,
    reconcile_call,
    QuotaExceededError,
    IntegrationCredentialsError,
)

logger = logging.getLogger(__name__)


class TyposquatEnrichmentMixin:
    """Per-registered-domain enrichment methods (HTTP/SSL/RDAP→WHOIS/email-auth).

    Shared by `TyposquatDetectTool` and `TyposquatEnrichTool`. Holds no
    discovery/generation logic — only the enrichment probes and their
    in-process rate-limiter state.
    """

    # SECONDARY RDAP/WHOIS smoother (see __init__): ~3 lookups/sec sustained,
    # burst up to 5. This is NOT the primary limiter — the cross-process
    # ProviderQuotaService checkout is (CLAUDE.md: the 5 agents do not coordinate
    # in-process). This only paces bursts inside one container.
    _RDAP_REFILL_PER_SEC = 3.0
    _RDAP_BUCKET_CAPACITY = 5.0

    # FEED-3 — on a download failure, retry after this short window instead of
    # serving an empty "clean" cache under the full 1h TTL.
    _OPENPHISH_FAILURE_RETRY_TTL = 120

    def __init__(self):
        super().__init__()
        # PhishTank rate limiter: 10 req/min (free tier)
        # Lock-based to prevent race conditions across concurrent executions
        self._pt_lock = asyncio.Lock()
        self._pt_last_reset = 0.0
        self._pt_count = 0

        # OpenPhish feed cache with lock and TTL (3600s = 1 hour, matches feed update interval)
        self._openphish_lock = asyncio.Lock()
        self._openphish_cache: Optional[Set[str]] = None
        self._openphish_cache_time = 0.0
        # FEED-3 — suppress re-fetch hammering during a recent-failure window so a
        # 20-domain batch doesn't serially re-curl the feed N times on an outage.
        self._openphish_failure_until = 0.0

        # VirusTotal rate limiter: 4 req/min (free tier)
        # Lock-based to prevent race conditions across concurrent executions
        self._vt_lock = asyncio.Lock()
        self._vt_last_reset = 0.0
        self._vt_count = 0

        # RDAP/WHOIS age-capture rate limiting. The PRIMARY limiter is the
        # cross-process ProviderQuotaService seam (checkout_provider('RDAP')) so
        # all 5 agent containers coordinate per CLAUDE.md — a bare in-process
        # semaphore does NOT coordinate across containers. The token bucket
        # below is only a SECONDARY in-process smoother for bursts within one
        # container, and the sole limiter when the backend has no 'RDAP' provider
        # row configured (keyless → checkout raises and we fall through to
        # local-only best-effort smoothing).
        self._rdap_lock = asyncio.Lock()
        self._rdap_tokens = float(self._RDAP_BUCKET_CAPACITY)
        self._rdap_last_refill = time.monotonic()

    # -- HTTP / SSL / title ----------------------------------------------------

    async def _check_http(self, domain: str) -> Dict[str, Any]:
        """Check if domain serves web content with redirect chain tracking.

        Returns dict with: has_content, status_code, redirect_chain, final_url.
        Follows Location headers manually up to 10 hops.
        """
        result = {
            'has_content': False,
            'status_code': 0,
            'redirect_chain': [],
            'final_url': f'http://{domain}',
        }
        current_url = f'http://{domain}'
        max_hops = 10

        try:
            for hop in range(max_hops):
                proc = await asyncio.create_subprocess_exec(
                    'curl', '-sI',
                    '--connect-timeout', '3', '--max-time', '5',
                    '-o', '-',
                    current_url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,  # #571 group leader for watchdog/reaper teardown
                )
                register_group(proc)
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                headers_text = stdout.decode('utf-8', errors='replace')

                # Parse status code from first line
                status_code = 0
                location = None
                for line in headers_text.split('\n'):
                    line = line.strip()
                    if line.upper().startswith('HTTP/') and ' ' in line:
                        parts = line.split(None, 2)
                        if len(parts) >= 2 and parts[1].isdigit():
                            status_code = int(parts[1])
                    elif line.lower().startswith('location:'):
                        location = line.split(':', 1)[1].strip()

                result['redirect_chain'].append({
                    'url': current_url,
                    'status_code': status_code,
                })

                # If not a redirect, stop
                if status_code < 300 or status_code >= 400 or not location:
                    result['has_content'] = 200 <= status_code <= 399
                    result['status_code'] = status_code
                    result['final_url'] = current_url
                    break

                # Resolve relative Location URLs (e.g. "/home") against the
                # current URL so we never fabricate a bogus host like
                # "http://home/". urljoin handles absolute, root-relative, and
                # path-relative redirects correctly.
                location = urljoin(current_url, location)

                current_url = location
            else:
                # Exhausted max hops
                result['status_code'] = status_code
                result['final_url'] = current_url

        except (asyncio.TimeoutError, Exception):
            pass

        return result

    async def _check_ssl(self, domain: str) -> Optional[Dict[str, Any]]:
        """Capture the TLS leaf certificate presented on port 443 (A4).

        Returns the parsed-certificate dict (issuer CN/O, subject CN, SAN DNS
        entries, validity window, SHA-256 fingerprint) when a certificate is
        presented, else ``None`` — so "has a certificate" stays derivable as
        ``result is not None`` (the boolean the envelope previously carried).

        The handshake is deliberately UNVERIFIED (``CERT_NONE``): self-signed
        and expired certificates on lookalike infrastructure are exactly the
        correlation intel we want, and the prior ``openssl s_client`` boolean
        also counted them as "has cert". Never raises — timeouts, refused
        connections, and handshake failures all return ``None``.
        """
        try:
            der = await asyncio.wait_for(
                self._fetch_peer_cert_der(domain), timeout=8,
            )
            if not der:
                return None
            return self._parse_tls_certificate(der)
        except (asyncio.TimeoutError, Exception):
            return None

    async def _fetch_peer_cert_der(self, domain: str) -> Optional[bytes]:
        """TLS-connect to ``domain:443`` (SNI set) and return the peer's leaf
        certificate in DER form, or ``None`` when no certificate was presented.
        Network/handshake errors propagate — ``_check_ssl`` owns the catch."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        writer = None
        try:
            _reader, writer = await asyncio.open_connection(
                domain, 443, ssl=ctx, server_hostname=domain,
            )
            ssl_obj = writer.get_extra_info('ssl_object')
            return ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    @staticmethod
    def _parse_tls_certificate(der: bytes) -> Optional[Dict[str, Any]]:
        """Parse a DER-encoded x509 leaf into the flat ``ssl_cert`` envelope
        fields. Pure (no I/O). Returns ``None`` when `cryptography` is absent
        or the blob is unparseable — the caller degrades to has-cert-only."""
        if _x509 is None:
            return None
        try:
            cert = _x509.load_der_x509_certificate(der)

            def _name_attr(name: Any, oid: Any) -> Optional[str]:
                attrs = name.get_attributes_for_oid(oid)
                return str(attrs[0].value) if attrs else None

            san_dns: List[str] = []
            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    _ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                )
                # Cap the list — wildcard/CDN certs can carry hundreds of SANs
                # and this lands in a JSON metadata column.
                san_dns = [
                    str(v)
                    for v in san_ext.value.get_values_for_type(_x509.DNSName)
                ][:50]
            except Exception:
                san_dns = []

            # not_valid_*_utc exist on cryptography>=42 (repo pins 44,<45); the
            # naive-datetime fallback keeps this safe on older wheels.
            not_before = getattr(cert, 'not_valid_before_utc', None) \
                or cert.not_valid_before
            not_after = getattr(cert, 'not_valid_after_utc', None) \
                or cert.not_valid_after

            return {
                'issuer_common_name': _name_attr(cert.issuer, _NameOID.COMMON_NAME),
                'issuer_organization': _name_attr(
                    cert.issuer, _NameOID.ORGANIZATION_NAME,
                ),
                'subject_common_name': _name_attr(cert.subject, _NameOID.COMMON_NAME),
                'san': san_dns,
                'not_before': not_before.isoformat() if not_before else None,
                'not_after': not_after.isoformat() if not_after else None,
                'sha256_fingerprint': cert.fingerprint(
                    _crypto_hashes.SHA256(),
                ).hex(),
            }
        except Exception:
            return None

    async def _get_page_title(self, domain: str) -> Optional[str]:
        """Fetch page title via curl."""
        try:
            proc = await asyncio.create_subprocess_exec(
                'curl', '-sL', '--connect-timeout', '3', '--max-time', '5',
                '-o', '-', f'http://{domain}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # #571 group leader for watchdog/reaper teardown
            )
            register_group(proc)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            html_text = stdout.decode('utf-8', errors='replace')
            match = re.search(r'<title[^>]*>(.*?)</title>', html_text, re.IGNORECASE | re.DOTALL)
            if match:
                return html.unescape(match.group(1).strip())[:255]
        except (asyncio.TimeoutError, Exception):
            pass
        return None

    async def _mx_lookup(self, domain: str) -> List[str]:
        """Lookup MX records for a domain (in-process async — no ``dig``)."""
        records, _ = await resolve_records(domain, 'MX')
        return records[:5]

    # -- ASN annotation (A3, Team Cymru IP→ASN over DNS) ------------------------

    # Cap the per-domain ASN fan-out: at most the first 8 resolved IPv4s are
    # annotated (bounds DNS work; lookalike hosting rarely spans more networks).
    _ASN_MAX_IPS = 8

    @staticmethod
    def _cymru_txt_fields(txt: str) -> List[str]:
        """Split a Team Cymru TXT payload into its pipe-delimited fields.

        dnspython's ``to_text()`` returns the character-string quoted (and a
        long record may be segmented into ``"a" "b"``); strip the quoting
        before splitting on ``|``.
        """
        cleaned = txt.replace('" "', '').strip().strip('"').strip()
        return [f.strip() for f in cleaned.split('|')]

    @classmethod
    def _parse_cymru_origin(cls, txt: str) -> Optional[Dict[str, Any]]:
        """Parse one ``origin.asn.cymru.com`` TXT record.

        Shape: ``"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"`` =
        ``ASN | BGP prefix | country | registry | allocated``. The ASN field
        may carry MULTIPLE space-separated ASNs (multi-origin prefix) — the
        first is taken. Returns ``None`` on any parse miss (fail soft).
        """
        try:
            fields = cls._cymru_txt_fields(txt)
            if not fields or not fields[0]:
                return None
            asn_token = fields[0].split()[0]
            if not asn_token.isdigit():
                return None
            return {
                'asn': int(asn_token),
                'bgp_prefix': fields[1] if len(fields) > 1 and fields[1] else None,
                'country': fields[2] if len(fields) > 2 and fields[2] else None,
                'registry': fields[3].lower() if len(fields) > 3 and fields[3] else None,
            }
        except Exception:
            return None

    @classmethod
    def _parse_cymru_asname(cls, txt: str) -> Optional[str]:
        """Parse the AS name from an ``AS<n>.asn.cymru.com`` TXT record.

        Shape: ``"15169 | US | arin | 2000-03-30 | GOOGLE, US"`` — the AS name
        is the LAST field (it may itself contain commas, never pipes).
        Returns ``None`` on any parse miss (fail soft).
        """
        try:
            fields = cls._cymru_txt_fields(txt)
            if len(fields) < 5 or not fields[-1]:
                return None
            return fields[-1][:255]
        except Exception:
            return None

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        parts = value.split('.')
        return len(parts) == 4 and all(
            p.isdigit() and 0 <= int(p) <= 255 for p in parts
        )

    async def _asn_lookup(self, domain: str) -> List[Dict[str, Any]]:
        """A3 — annotate the domain's resolved IPv4s with their hosting ASN.

        Passive, keyless Team Cymru IP→ASN mapping done entirely over DNS TXT
        (reuses the shared in-process async resolver — no new client, no HTTP):
        ``d.c.b.a.origin.asn.cymru.com`` for the origin ASN/prefix, then
        ``AS<n>.asn.cymru.com`` for the AS name. Two lookalikes parked in the
        same ASN/netblock is a same-operator correlation signal.

        Resolves the domain's A records first (this tool does not otherwise
        carry them), caps at the first ``_ASN_MAX_IPS`` IPv4s, dedups by ASN
        across the IPs, and fails soft everywhere: timeout / NXDOMAIN / parse
        miss skips that IP, never raises. Empty list when nothing resolved.
        """
        results: List[Dict[str, Any]] = []
        seen_asns: Set[int] = set()
        try:
            ips, _status = await resolve_records(domain, 'A')
        except Exception:
            return results
        for ip in [i for i in ips if self._is_ipv4(i)][:self._ASN_MAX_IPS]:
            try:
                reversed_ip = '.'.join(reversed(ip.split('.')))
                txts, status = await resolve_records(
                    f'{reversed_ip}.origin.asn.cymru.com', 'TXT',
                )
                if status != 'NOERROR' or not txts:
                    continue
                origin = self._parse_cymru_origin(txts[0])
                if not origin or origin['asn'] in seen_asns:
                    continue
                seen_asns.add(origin['asn'])
                name: Optional[str] = None
                try:
                    name_txts, name_status = await resolve_records(
                        f"AS{origin['asn']}.asn.cymru.com", 'TXT',
                    )
                    if name_status == 'NOERROR' and name_txts:
                        name = self._parse_cymru_asname(name_txts[0])
                except Exception:
                    name = None
                results.append({
                    'asn': origin['asn'],
                    'name': name,
                    'bgp_prefix': origin['bgp_prefix'],
                    'country': origin['country'],
                    'registry': origin['registry'],
                })
            except Exception:
                # Fail soft per IP — an unparseable/unreachable mapping for one
                # address must never sink the whole enrichment row.
                continue
        return results

    # -- WHOIS / RDAP registration-age -----------------------------------------

    @staticmethod
    def _normalize_whois_field(value: Optional[str]) -> Optional[str]:
        """Normalize a WHOIS field value, returning None for privacy-redacted values."""
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        redaction_patterns = [
            "redacted for privacy",
            "data protected",
            "gdpr masked",
            "not disclosed",
            "registration private",
            "contact privacy",
            "whoisguard protected",
            "identity protection",
            "perfect privacy",
            "domains by proxy",
            "privacy service provided",
            "statutory masking enabled",
            "redacted",
            "not applicable",
            "data redacted",
        ]
        value_lower = value.lower()
        for pattern in redaction_patterns:
            if pattern in value_lower:
                return None
        return value

    async def _whois_lookup(self, domain: str, _retry: bool = True) -> Dict[str, Any]:
        """Lookup WHOIS data for a domain. Retries once on timeout.

        On a genuine lookup FAILURE (timeout after retry, or an exception) the
        returned dict carries ``whois_failed: True`` so the backend can PRESERVE
        previously-persisted WHOIS data instead of clobbering it with nulls. A
        successful lookup that simply has no registrar (e.g. a privacy-redacted
        or sparse TLD) returns ``whois_failed: False`` — that empty IS authentic
        and may be written.
        """
        empty = {'registrar': None, 'created': None, 'expires': None, 'nameservers': [],
                 'registrant_email': None, 'registrant_org': None, 'registrant_name': None,
                 'registrant_country': None, 'whois_failed': True}
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                'whois', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # #571 group leader for watchdog/reaper teardown
            )
            register_group(proc)
            # #1048 — tightened from 15s; port-43 WHOIS is the slowest source and
            # must not dominate the enrichment budget. Single-shot (no retry).
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            text = stdout.decode('utf-8', errors='replace')

            registrar = None
            created = None
            expires = None
            nameservers = []
            registrant_email = None
            registrant_org = None
            registrant_name = None
            registrant_country = None

            for line in text.split('\n'):
                line_lower = line.lower().strip()
                if not registrar and ('registrar:' in line_lower or 'registrar name:' in line_lower):
                    registrar = line.split(':', 1)[1].strip()
                if not created and ('creation date:' in line_lower or 'created:' in line_lower or 'registered on:' in line_lower):
                    created = line.split(':', 1)[1].strip()
                if not expires and ('expir' in line_lower and 'date' in line_lower):
                    expires = line.split(':', 1)[1].strip()
                if 'name server:' in line_lower or 'nserver:' in line_lower:
                    ns = line.split(':', 1)[1].strip().lower()
                    if ns and ns not in nameservers:
                        nameservers.append(ns)
                if not registrant_email and (line_lower.startswith('registrant email:') or line_lower.startswith('registrant contact email:')):
                    registrant_email = self._normalize_whois_field(line.split(':', 1)[1])
                if not registrant_org and (line_lower.startswith('registrant organization:') or line_lower.startswith('registrant org:') or line_lower.startswith('org-name:')):
                    registrant_org = self._normalize_whois_field(line.split(':', 1)[1])
                if not registrant_name and line_lower.startswith('registrant name:') and 'org' not in line_lower:
                    registrant_name = self._normalize_whois_field(line.split(':', 1)[1])
                if not registrant_country and line_lower.startswith('registrant country:'):
                    registrant_country = self._normalize_whois_field(line.split(':', 1)[1])

            result = {
                'registrar': registrar,
                'created': created,
                'expires': expires,
                'nameservers': nameservers[:4],
                'registrant_email': registrant_email,
                'registrant_org': registrant_org,
                'registrant_name': registrant_name,
                'registrant_country': registrant_country,
                'whois_failed': False,
            }
            logger.info(f"[Typosquat] WHOIS {domain}: registrar={registrar}, created={created}, ns={len(nameservers)}, output_len={len(text)}")
            return result
        except asyncio.TimeoutError:
            # #1048 — port-43 WHOIS is the slowest, worst-behaved enrichment
            # source; a per-domain retry (2× the already-long timeout) was the
            # dominant driver of enrichment blowing the job budget at depth.
            # Single-shot now: kill the timed-out child and skip (RDAP is the
            # primary age source anyway; WHOIS is fallback). `_retry` retained
            # for signature compatibility but no longer loops.
            await terminate_group(proc)
            logger.warning(f"[Typosquat] WHOIS timeout for {domain}, skipping (single-shot)")
            return empty
        except Exception as e:
            logger.warning(f"[Typosquat] WHOIS error for {domain}: {e}")
            return empty

    @staticmethod
    def _to_iso(value: Any) -> Optional[str]:
        """Normalize an asyncwhois date (datetime / list / str) to clean ISO.

        Emits ``%Y-%m-%dT%H:%M:%SZ`` so the value matches the first format the
        scorer (`_score_result`) and the backend `parseWhoisDate` already accept.
        """
        if value is None:
            return None
        if isinstance(value, (list, tuple)):
            value = next((v for v in value if v is not None), None)
            if value is None:
                return None
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%dT%H:%M:%SZ')
        text = str(value).strip()
        return text or None

    async def _rdap_throttle(self) -> None:
        """SECONDARY in-process token-bucket smoother for RDAP/WHOIS calls.

        Not the primary limiter (that is the cross-process checkout); this just
        paces bursts within a single container so a large registered-domain
        batch does not hammer registry RDAP endpoints from one agent at once.
        """
        async with self._rdap_lock:
            now = time.monotonic()
            elapsed = now - self._rdap_last_refill
            self._rdap_last_refill = now
            self._rdap_tokens = min(
                self._RDAP_BUCKET_CAPACITY,
                self._rdap_tokens + elapsed * self._RDAP_REFILL_PER_SEC,
            )
            if self._rdap_tokens < 1.0:
                wait = (1.0 - self._rdap_tokens) / self._RDAP_REFILL_PER_SEC
                await asyncio.sleep(wait)
                self._rdap_tokens = 0.0
            else:
                self._rdap_tokens -= 1.0

    async def _rdap_created(self, domain: str) -> Tuple[Optional[str], bool]:
        """RDAP-primary registration-date lookup → (clean ISO string | None, age_throttled).

        Reads RDAP `events[].eventAction=="registration".eventDate` (asyncwhois
        surfaces it as the parsed ``CREATED`` key) which is a clean ISO date and
        bypasses the port-43 first-match `created:` artifact. Returns None for
        ccTLDs lacking RDAP (no IANA bootstrap entry) — the caller then falls
        back to the existing hardened port-43 `_whois_lookup` `created`.

        WHOIS-2 age-confidence: the second tuple element is True ONLY when the
        lookup was SKIPPED by a tenant rate-limit / quota (QuotaExceededError) —
        i.e. the age is UNKNOWN because we were throttled, NOT because the
        registry has no date. The backend threads this so a fresh clone caught
        during an RDAP rate-limit is HELD for re-sweep instead of being
        fail-closed to 'stale' on its null age. Every other no-date outcome
        (ccTLD without RDAP, parse miss, network error → port-43 still runs)
        returns False so a genuine gap keeps the existing FP-protecting cap.

        Rate-limited through the cross-process ProviderQuotaService seam
        (synthetic 'RDAP' provider). If the backend has no RDAP provider row
        (keyless provider), checkout raises IntegrationCredentialsError and we
        proceed best-effort under the local smoother only. A QuotaExceededError
        (tenant cap hit) skips the lookup so we never breach a configured cap.
        """
        if asyncwhois is None:
            return None, False

        lease: Optional[str] = None
        try:
            checkout = await checkout_provider('RDAP', requested_units=1)
            lease = checkout.get('leaseToken')
        except QuotaExceededError:
            # Respect a configured cap — skip the lookup (port-43 fallback still
            # runs in _whois_lookup). Age is UNKNOWN-because-throttled, not a gap.
            return None, True
        except IntegrationCredentialsError:
            # No 'RDAP' provider configured (keyless) or transient backend error
            # — fall through to a best-effort lookup paced by the local smoother.
            lease = None
        except Exception:
            lease = None

        await self._rdap_throttle()

        created_iso: Optional[str] = None
        success = False
        try:
            _query, parsed = await asyncwhois.aio_rdap(domain)
            if parsed:
                created = None
                if _AwKeys is not None:
                    created = parsed.get(_AwKeys.CREATED)
                if created is None:
                    created = parsed.get('created')
                created_iso = self._to_iso(created)
            success = created_iso is not None
        except Exception as e:
            # ccTLD without RDAP, network error, parse miss — fall back silently.
            logger.debug(f"[Typosquat] RDAP age lookup failed for {domain}: {e}")
        finally:
            if lease:
                try:
                    await reconcile_call(
                        'RDAP', lease, units=1, success=success,
                        error_code=None if success else 'rdap_no_date',
                    )
                except Exception:
                    pass

        # age_throttled=False: a None here is a genuine gap / port-43 fallback
        # case, not a rate-limit (the only throttle path returns early above).
        return created_iso, False

    # -- Threat feeds: VirusTotal / PhishTank / OpenPhish ----------------------

    async def _check_virustotal(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check domain reputation via VirusTotal API v3.

        Returns detection stats dict or None if VT_API_KEY is not set or on error.
        Rate-limited to 4 requests per minute (free tier).

        TODO(T2.7 — tracked in roadmaps/core-platform.md "Split agent/tools/
        typosquat_detect.py" entry): Migrate to ProviderQuotaService.checkout
        once VIRUSTOTAL is added to the IntegrationProvider enum. The in-process
        asyncio.Lock below only synchronizes inside ONE agent container; with
        5 agents the effective rate is 20/min, not 4/min — risking a VT ban.
        Deferred from the 2026-05-19 cleanup pass because (a) the enum addition
        + Prisma migration falls under the locked "large refactors land as
        separate PRs" decision, and (b) wiring checkout() without an Integration
        row makes the call fail-closed for tenants that haven't configured a VT
        key — a behavior change, not a cleanup. The roadmap entry covers both.
        """
        api_key = os.environ.get('VT_API_KEY')
        if not api_key:
            return None

        # Rate limiting: 4 requests per 60 seconds (lock-based for concurrency safety)
        async with self._vt_lock:
            now = time.time()
            if now - self._vt_last_reset >= 60:
                self._vt_last_reset = now
                self._vt_count = 0
            if self._vt_count >= 4:
                wait_time = 60 - (now - self._vt_last_reset)
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                self._vt_last_reset = time.time()
                self._vt_count = 0
            self._vt_count += 1

        try:
            proc = await asyncio.create_subprocess_exec(
                'curl', '-s', '--connect-timeout', '5', '--max-time', '10',
                '-H', f'x-apikey: {api_key}',
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # #571 group leader for watchdog/reaper teardown
            )
            register_group(proc)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            data = json.loads(stdout.decode('utf-8', errors='replace'))
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            total = malicious + suspicious + harmless + undetected
            result = {
                'malicious': malicious,
                'suspicious': suspicious,
                'total': total,
            }
            logger.info(f"[Typosquat] VT {domain}: malicious={malicious}, suspicious={suspicious}, total={total}")
            return result
        except (asyncio.TimeoutError, json.JSONDecodeError, Exception) as e:
            logger.warning(f"[Typosquat] VT error for {domain}: {e}")
            return None

    async def _check_phishtank(self, domain: str) -> bool:
        """Check if domain is in PhishTank database.

        Uses PhishTank API (POST checkurl). Requires PHISHTANK_API_KEY env var.
        Rate-limited to 10 requests per minute (free tier).
        Returns True if domain is a verified phish, False otherwise.

        TODO(T2.7 — tracked in roadmaps/core-platform.md "Split agent/tools/
        typosquat_detect.py" entry): Migrate to ProviderQuotaService.checkout
        once PHISHTANK is added to the IntegrationProvider enum. Same
        cross-container rate-limit problem as VirusTotal above (5 agents ×
        10/min = effective 50/min, free tier limit is 10/min). Deferred from
        the 2026-05-19 cleanup pass per the same reasoning as VirusTotal above.
        """
        api_key = os.environ.get('PHISHTANK_API_KEY')
        if not api_key:
            return False

        # Rate limiting: 10 requests per 60 seconds (lock-based for concurrency safety)
        async with self._pt_lock:
            now = time.time()
            if now - self._pt_last_reset >= 60:
                self._pt_last_reset = now
                self._pt_count = 0
            if self._pt_count >= 10:
                wait_time = 60 - (now - self._pt_last_reset)
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                self._pt_last_reset = time.time()
                self._pt_count = 0
            self._pt_count += 1

        try:
            proc = await asyncio.create_subprocess_exec(
                'curl', '-s', '--connect-timeout', '5', '--max-time', '10',
                '-X', 'POST',
                '-d', f'url=http://{domain}&format=json&app_key={api_key}',
                'http://checkurl.phishtank.com/checkurl/',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # #571 group leader for watchdog/reaper teardown
            )
            register_group(proc)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            data = json.loads(stdout.decode('utf-8', errors='replace'))
            results = data.get('results', {})
            in_database = results.get('in_database', False)
            verified = results.get('verified', False)
            if in_database and verified:
                logger.warning(f"[Typosquat] PhishTank MATCH: {domain} is a verified phish")
                return True
            return False
        except (asyncio.TimeoutError, json.JSONDecodeError, Exception) as e:
            logger.warning(f"[Typosquat] PhishTank error for {domain}: {e}")
            return False

    async def _load_openphish_feed(self) -> Tuple[Set[str], bool]:
        """Download the OpenPhish feed and cache it with TTL.

        Feed URL: https://openphish.com/feed.txt (updated hourly).
        Cache TTL: 3600 seconds (1 hour). Returns (urls, available) — `available`
        is False ONLY when the feed could not be loaded AND no prior good cache
        exists, so the caller treats candidates as UNSWEPT (not clean) during an
        outage (FEED-3). Uses asyncio.Lock to prevent concurrent fetch races.
        """
        def _resolve_without_fetch(now: float):
            """Return a (urls, available) decision WITHOUT fetching, or None if a
            live fetch is needed. Covers the valid-cache fast path AND the
            recent-failure window (so a batch doesn't re-curl N times on outage)."""
            if self._openphish_cache is not None and (now - self._openphish_cache_time) < 3600:
                return self._openphish_cache, True
            if now < self._openphish_failure_until:
                # Within the post-failure retry window: serve a prior good cache
                # stale-but-good, else report UNAVAILABLE (never empty-clean).
                if self._openphish_cache:
                    return self._openphish_cache, True
                return set(), False
            return None

        now = time.time()
        decided = _resolve_without_fetch(now)
        if decided is not None:
            return decided

        async with self._openphish_lock:
            # Re-check inside lock (another coroutine may have populated it or
            # entered the failure window).
            now = time.time()
            decided = _resolve_without_fetch(now)
            if decided is not None:
                return decided

            try:
                proc = await asyncio.create_subprocess_exec(
                    'curl', '-s', '--connect-timeout', '5', '--max-time', '15',
                    'https://openphish.com/feed.txt',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,  # #571 group leader for watchdog/reaper teardown
                )
                register_group(proc)
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
                text = stdout.decode('utf-8', errors='replace').strip()
                urls = set()
                for line in text.split('\n'):
                    line = line.strip()
                    if line:
                        urls.add(line)
                # FEED-3 — an empty body (curl 200 on a rate-limit/empty page, or
                # 4xx/5xx body that yields no URLs) is NOT a clean feed; treat it
                # like a fetch failure rather than caching an empty "clean" set.
                if not urls:
                    raise ValueError('OpenPhish feed returned no URLs (empty/error body)')
                self._openphish_cache = urls
                self._openphish_cache_time = time.time()
                self._openphish_failure_until = 0.0
                logger.info(f"[Typosquat] OpenPhish feed loaded: {len(urls)} URLs")
                return urls, True
            except (asyncio.TimeoutError, Exception) as e:
                logger.warning(f"[Typosquat] OpenPhish feed error: {e}")
                # FEED-3 — never cache an empty "clean" set under the 1h TTL. Open
                # a short retry window (suppresses per-domain re-fetch hammering);
                # serve a prior good cache stale-but-good, else report UNAVAILABLE
                # so candidates are NOT scored clean for an hour during an outage.
                self._openphish_failure_until = time.time() + self._OPENPHISH_FAILURE_RETRY_TTL
                if self._openphish_cache:
                    return self._openphish_cache, True
                return set(), False

    async def _check_openphish(self, domain: str) -> Tuple[Optional[str], bool]:
        """Check whether `domain` is the HOST of any OpenPhish feed URL.

        Returns (matched_url, feed_available). FEED-1/PERM-8: matches on URL HOST
        equality / subdomain-suffix (`urlparse(url).hostname == domain` or
        `.endswith('.'+domain)`), NOT a raw substring — so a structure-only
        candidate that merely shares a substring with an unrelated feed URL is no
        longer phantom-promoted to HIGH. FEED-5: returns the matched URL as
        analyst evidence. feed_available=False during an outage (FEED-3).
        """
        feed, available = await self._load_openphish_feed()
        if not available:
            return None, False

        domain_lower = domain.lower().strip()
        for url in feed:
            try:
                host = (urlparse(url if '://' in url else 'http://' + url).hostname or '').lower()
            except Exception:
                continue
            if host == domain_lower or host.endswith('.' + domain_lower):
                logger.warning(f"[Typosquat] OpenPhish MATCH: {domain} is the host of {url}")
                return url, True
        return None, True

    # -- Email authentication: SPF / DMARC / DKIM ------------------------------

    async def _check_spf(self, domain: str) -> Dict[str, Any]:
        """Check SPF record for a domain via dig TXT.

        Returns dict with: has_spf, spf_record, spf_policy.
        """
        # POST-1 — `spf_unswept` distinguishes "the resolver gave no usable answer"
        # (SERVFAIL/REFUSED/timeout/error) from a genuinely empty TXT, so the
        # scorer does NOT add phantom no-SPF risk for a blind resolver. NOTE:
        # `dig +short` exits 0 for SERVFAIL (it IS a DNS response), so we run the
        # FULL query and parse the `status:` header to detect a non-answer.
        result = {'has_spf': False, 'spf_record': None, 'spf_policy': None, 'spf_unswept': False}
        try:
            proc = await asyncio.create_subprocess_exec(
                'dig', 'TXT', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # #571 group leader for watchdog/reaper teardown
            )
            register_group(proc)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            out = stdout.decode('utf-8', errors='replace')
            status_m = re.search(r'status:\s*([A-Z]+)', out)
            status = status_m.group(1).upper() if status_m else ''
            # SERVFAIL/REFUSED, or no header at all (rc 9 / no servers reached) →
            # unswept, NOT clean. NOERROR (incl. empty/NODATA) falls through to
            # parsing so a genuine no-SPF still scores.
            if status in ('SERVFAIL', 'REFUSED') or (not status and proc.returncode not in (0, None)):
                result['spf_unswept'] = True
                return result
            for line in out.split('\n'):
                low = line.lower()
                if 'v=spf1' in low and '\ttxt\t' in low:
                    result['has_spf'] = True
                    result['spf_record'] = line.split('TXT', 1)[-1].strip().strip('"')
                    for policy in ['-all', '~all', '+all', '?all']:
                        if policy in low:
                            result['spf_policy'] = policy
                            break
                    break
        except (asyncio.TimeoutError, Exception) as e:
            result['spf_unswept'] = True
            logger.warning(f"[Typosquat] SPF check error for {domain}: {e}")
        return result

    async def _check_dmarc(self, domain: str) -> Dict[str, Any]:
        """Check DMARC record for a domain via dig TXT _dmarc.{domain}.

        Returns dict with: has_dmarc, dmarc_record, dmarc_policy.
        """
        # POST-1 — `dmarc_unswept` distinguishes a blind resolver from a genuine
        # no-DMARC, so the scorer does not add phantom no-DMARC risk on a timeout.
        result = {'has_dmarc': False, 'dmarc_record': None, 'dmarc_policy': None, 'dmarc_unswept': False}
        try:
            proc = await asyncio.create_subprocess_exec(
                'dig', 'TXT', f'_dmarc.{domain}',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,  # #571 group leader for watchdog/reaper teardown
            )
            register_group(proc)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            out = stdout.decode('utf-8', errors='replace')
            status_m = re.search(r'status:\s*([A-Z]+)', out)
            status = status_m.group(1).upper() if status_m else ''
            if status in ('SERVFAIL', 'REFUSED') or (not status and proc.returncode not in (0, None)):
                result['dmarc_unswept'] = True
                return result
            for line in out.split('\n'):
                low = line.lower()
                if 'v=dmarc1' in low and '\ttxt\t' in low:
                    result['has_dmarc'] = True
                    result['dmarc_record'] = line.split('TXT', 1)[-1].strip().strip('"')
                    # Extract policy (p=none|quarantine|reject)
                    match = re.search(r'p\s*=\s*(none|quarantine|reject)', line, re.IGNORECASE)
                    if match:
                        result['dmarc_policy'] = match.group(1).lower()
                    break
        except (asyncio.TimeoutError, Exception) as e:
            result['dmarc_unswept'] = True
            logger.warning(f"[Typosquat] DMARC check error for {domain}: {e}")
        return result

    async def _check_dkim(self, domain: str) -> Dict[str, Any]:
        """Check DKIM records for a domain by trying common selectors.

        Tries selectors: default, google, selector1, selector2, k1.
        Returns dict with: has_dkim, dkim_selector.
        """
        result: Dict[str, Any] = {'has_dkim': False, 'dkim_selector': None}
        selectors = ['default', 'google', 'selector1', 'selector2', 'k1']
        for selector in selectors:
            try:
                proc = await asyncio.create_subprocess_exec(
                    'dig', 'TXT', '+short', f'{selector}._domainkey.{domain}',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    start_new_session=True,  # #571 group leader for watchdog/reaper teardown
                )
                register_group(proc)
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
                text = stdout.decode('utf-8', errors='replace').strip()
                if text and 'v=dkim1' in text.lower():
                    result['has_dkim'] = True
                    result['dkim_selector'] = selector
                    break
            except (asyncio.TimeoutError, Exception):
                continue
        return result

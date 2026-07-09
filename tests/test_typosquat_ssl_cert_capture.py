"""A4 — TLS leaf-certificate capture for lookalike correlation.

`_check_ssl` used to reduce the whole handshake to a boolean (openssl rc==0),
discarding the certificate detail (issuer, SAN, fingerprint) that lets an
analyst connect domains run by the same operator. It now returns a parsed
dict when a cert is presented, None otherwise — "has certificate" stays
derivable as `result is not None`.

No network calls: the cert is generated in-test with `cryptography` (the
repo's pinned <48 version) and the socket leg (`_fetch_peer_cert_der`) is
monkeypatched. Fictitious brand only (lumenfield.test).
"""

import asyncio
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from lib.typosquat_enrich_helpers import TyposquatEnrichmentMixin


class _Enricher(TyposquatEnrichmentMixin):
    """Bare mixin host — the mixin owns all state its methods need."""


NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2026, 4, 1, tzinfo=datetime.timezone.utc)


def _make_self_signed_der(
    subject_cn='lumenfield-login.test',
    issuer_cn='lumenfield-login.test',
    issuer_org='Test Phish CA',
    san=('lumenfield-login.test', 'www.lumenfield-login.test'),
):
    """Self-signed leaf mimicking what a lookalike host presents."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert, cert.public_bytes(Encoding.DER)


class TestParseTlsCertificate:
    def test_parses_issuer_subject_san_validity_fingerprint(self):
        cert, der = _make_self_signed_der()
        parsed = TyposquatEnrichmentMixin._parse_tls_certificate(der)
        assert parsed is not None
        assert parsed['issuer_common_name'] == 'lumenfield-login.test'
        assert parsed['issuer_organization'] == 'Test Phish CA'
        assert parsed['subject_common_name'] == 'lumenfield-login.test'
        assert parsed['san'] == [
            'lumenfield-login.test',
            'www.lumenfield-login.test',
        ]
        assert parsed['not_before'] == NOT_BEFORE.isoformat()
        assert parsed['not_after'] == NOT_AFTER.isoformat()
        # SHA-256 fingerprint must match cryptography's own computation and be
        # plain lowercase hex (correlation key across domains).
        assert parsed['sha256_fingerprint'] == cert.fingerprint(hashes.SHA256()).hex()
        assert len(parsed['sha256_fingerprint']) == 64

    def test_missing_san_and_org_degrade_to_empty_not_raise(self):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'lumenfield.test')])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOT_BEFORE)
            .not_valid_after(NOT_AFTER)
            .sign(key, hashes.SHA256())
        )
        parsed = TyposquatEnrichmentMixin._parse_tls_certificate(
            cert.public_bytes(Encoding.DER),
        )
        assert parsed is not None
        assert parsed['san'] == []
        assert parsed['issuer_organization'] is None

    def test_garbage_der_returns_none(self):
        assert TyposquatEnrichmentMixin._parse_tls_certificate(b'not a cert') is None


class TestCheckSsl:
    def setup_method(self):
        self.tool = _Enricher()

    def test_returns_parsed_dict_when_cert_presented(self, monkeypatch):
        _cert, der = _make_self_signed_der()

        async def fake_fetch(domain):
            assert domain == 'lumenfield-login.test'
            return der

        monkeypatch.setattr(self.tool, '_fetch_peer_cert_der', fake_fetch)
        result = asyncio.run(self.tool._check_ssl('lumenfield-login.test'))
        assert result is not None  # has_ssl_cert derives from this
        assert result['issuer_organization'] == 'Test Phish CA'
        assert result['sha256_fingerprint']

    @pytest.mark.parametrize(
        'failure',
        [
            ConnectionRefusedError('refused'),
            asyncio.TimeoutError(),
            OSError('no route'),
            # e.g. TLS alert / not-TLS-on-443
            ValueError('handshake failure'),
        ],
    )
    def test_probe_failures_return_none_never_raise(self, monkeypatch, failure):
        async def fake_fetch(domain):
            raise failure

        monkeypatch.setattr(self.tool, '_fetch_peer_cert_der', fake_fetch)
        assert asyncio.run(self.tool._check_ssl('lumenfield-login.test')) is None

    def test_no_cert_presented_returns_none(self, monkeypatch):
        async def fake_fetch(domain):
            return None

        monkeypatch.setattr(self.tool, '_fetch_peer_cert_der', fake_fetch)
        assert asyncio.run(self.tool._check_ssl('lumenfield-login.test')) is None

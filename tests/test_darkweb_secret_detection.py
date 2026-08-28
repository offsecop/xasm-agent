"""Agent-side Layer-A lock for the GitHub leaked-credential DETECTION layer
(#1474).

The existing DRP suite only replays fabricated tool OUTPUT through ingestion, so
it never exercises the live-detection primitives — `_SECRET_PATTERNS`, the
charset-aware entropy gate `_fragment_has_secret`, the generic quoted-assignment
regex, the verification-verdict split, and the on-demand full-cohort sweep. This
file drives those primitives directly over a SYNTHETIC corpus: one positive plus
one hard-negative per credential family, plus the JSON-shape / compound-key /
hex-token cases the pre-#1474 gate missed.

EVERY credential literal here is FABRICATED and authenticates to nothing — these
are detection fixtures, not secrets. Only the fictitious brand `lumenfield.test`
/ `lumenfield-demo.com` and `.test`/example domains appear (synthetic-data
principle: no real client brand string in agent/tools or agent/lib).
"""

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tools.darkweb_monitor import DarkWebMonitorTool


@pytest.fixture
def tool():
    t = DarkWebMonitorTool()
    t._source_status = {}
    t._dork_coverage = []
    return t


def _run(coro):
    return asyncio.run(coro)


# ── P0.1 — one POSITIVE per credential family ─────────────────────────────────
# Vendor-prefixed shapes deliberately use LOW-entropy bodies (e.g. all-zeros)
# where possible, proving the dedicated prefix REGEX fires — not luck via the
# entropy gate.
POSITIVES = {
    'aws_access_key': 'AWS_ACCESS_KEY_ID=AKIAEXAMPLE0000FAKEK',
    'github_token': 'token: ghp_FAKE00example00000000000000000000Token01',
    # Build vendor-shaped fixtures at runtime so repository push protection
    # does not mistake the inert values for live credentials.
    'slack_token': 'xoxb-' + '0000000000-0000000000-FAKEexampleTokenABCdef0000',
    'google_api_key': 'AIzaFAKE0example0000Token00000abcXYZ1234',
    'openai_key': 'OPENAI_API_KEY=sk-FAKE00example00Token00000abcXYZ1234567890',
    'private_key': '-----BEGIN OPENSSH PRIVATE KEY-----',
    # #1474 net-new families:
    'stripe_secret_low_entropy': 'sk_live_00000000000000000000',
    'stripe_corpus': '"secret_key": "sk_' + 'live_51AbCdEfGhIjKlMnOpQrStUvWx0FAKE"',
    'stripe_webhook': 'whsec_ABCdef0123456789ABCdef0123',
    'twilio_account_sid_hex': 'A' + 'C0123456789abcdef0123456789abcdef',
    'twilio_api_key_hex': 'S' + 'K0123456789abcdef0123456789abcdef',
    'sendgrid_corpus': '"api_key": "SG.FAKEexample0000.aB9cD2eF7gH4iJ8kL3mN6oP1qR5sT0uVwXyZ"',
    'gitlab_pat': 'gl' + 'pat-ABCdef0123456789ABCd',
    'gcp_service_account_json': '{ "type": "service_account", "project_id": "lumenfield-demo" }',
    'azure_storage_key': 'AccountKey=aB9cD2eF7gH4iJ8kL3mN6oP1qR5sT0uVwXyZ0123456789abcdEF==',
    'jwt': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsdW1lbmZpZWxkLWRlbW8ifQ.FAKEsignature00abcXYZ',
    'db_uri_postgres': 'postgres://lumenfield_app:Zx7Qw2Rt9Kp4Lm8Vb3Nc6@db.lumenfield-demo.com:5432/prod',
    'db_uri_mongodb_srv': 'mongodb+srv://admin:S3cr3tPass00@cluster0.mongodb.net',
    'git_credentials_https': 'https://lumenfield-ci:Zx7Qw2Rt9Kp4Lm8Vb3Nc6yH1jD0sGaF5tW8uE3pQ@github.com',
    'npm_auth_token': '//registry.npmjs.org/:_authToken=npm_Zx7Qw2Rt9Kp4Lm8Vb3Nc6yH1jD0sGaF5tW8uE3',
}

# ── hard NEGATIVES — must NOT be flagged (precision) ──────────────────────────
NEGATIVES = {
    'commit_sha40': 'Merge commit 356a192b7913b04c54574d18c28d46e6395428ab landed',
    'md5_digest': 'checksum d41d8cd98f00b204e9800998ecf8427e verified ok',
    'sha256_digest': 'digest e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'hex_color': 'theme color #a1b2c3 and #ffffff border-radius',
    'benign_brand_mention': 'a helper library for lumenfield oauth flows',
    'password_from_env': 'password = get_password_from_env()',
    'short_hex_id': 'build id: abc123def456',
    'plain_brand_url': 'see https://api.lumenfield-demo.com/v1/status for docs',
}


@pytest.mark.parametrize('name', sorted(POSITIVES))
def test_positive_family_is_flagged(tool, name):
    assert tool._fragment_has_secret(POSITIVES[name]) is True, (
        f'{name} should be detected as a secret'
    )


@pytest.mark.parametrize('name', sorted(NEGATIVES))
def test_hard_negative_is_not_flagged(tool, name):
    assert tool._fragment_has_secret(NEGATIVES[name]) is False, (
        f'{name} must NOT be flagged (false-positive regression)'
    )


# ── P0.2 — hex blind-spot: 32-hex Twilio-SID-shaped token reachable, bare
#           commit SHA / hex colour are NOT (charset-aware entropy gate) ───────

def test_hex_secret_in_credential_context_is_flagged(tool):
    # 32-hex token with a credential keyword nearby → hex entropy path fires.
    frag = 'twilio_auth_token = 0123456789abcdef0123456789abcdef'
    assert tool._fragment_has_secret(frag) is True


def test_vendor_prefixed_hex_flagged_without_context(tool):
    # A Twilio AC-prefixed SID needs NO surrounding keyword — the prefix regex
    # catches it (context-free), closing the blind spot the entropy gate can't.
    assert tool._fragment_has_secret('A' + 'C0123456789abcdef0123456789abcdef') is True


def test_bare_commit_sha_not_flagged(tool):
    # 40-hex, no credential context → identifier, not a secret.
    assert tool._fragment_has_secret('356a192b7913b04c54574d18c28d46e6395428ab') is False


def test_hex_color_not_flagged(tool):
    assert tool._fragment_has_secret('#a1b2c3') is False


# ── P0.3 — generic quoted-assignment: JSON `"key":"val"` + compound keys ──────

def test_json_shape_api_key_flagged(tool):
    assert tool._fragment_has_secret('"api_key": "aK9fZ2qR7xL4mB8nV3cP6tW1yH5jD0sG"') is True


def test_json_shape_client_secret_flagged(tool):
    assert tool._fragment_has_secret('"client_secret": "s3cr3tEXAMPLE_Qw9Zx2Rt7Kp4Lm8Vb3Nc6yH1"') is True


def test_compound_secret_key_flagged(tool):
    assert tool._fragment_has_secret('SECRET_KEY = "Zx7Qw2Rt9Kp4Lm8Vb3Nc6yH1jD0sGaF"') is True


def test_compound_django_secret_key_flagged(tool):
    assert tool._fragment_has_secret('DJANGO_SECRET_KEY="aB9cD2eF7gH4iJ8kL3mN6oP1qR5sT0uV"') is True


def test_compound_db_password_flagged(tool):
    assert tool._fragment_has_secret('DB_PASSWORD: "Zx7Qw2Rt9Kp4Lm8Vb3Nc6yH1jD0"') is True


def test_legacy_key_equals_val_still_flagged(tool):
    # No regression on the pre-#1474 `key = "val"` / YAML `key: "val"` shapes.
    assert tool._fragment_has_secret('api_key = "aBcDeFgHiJkLmN12"') is True
    assert tool._fragment_has_secret('password: "Zx7Qw2Rt9Kp4Lm8Vb3Nc6yH1jD0sGaF"') is True


def test_prose_quoted_value_not_flagged(tool):
    # A quoted value containing spaces is prose, not a credential → no match.
    assert tool._fragment_has_secret('secret = "this is a description"') is False


# ── P1.6 — verification verdict split (unsupported-provider ≠ unverified) ──────

def _exposed_row():
    return {
        'matchType': 'EXPOSED_SECRET',
        'severity': 'HIGH',
        'riskScore': 70,
        'metadata': {'repository': 'lumenfield-org/config'},
    }


def test_unsupported_provider_keeps_candidate_severity(tool):
    out = _run(tool._apply_secret_verification(
        [_exposed_row()], verifier=lambda url: {'verdict': 'unsupported-provider'},
    ))
    r = out[0]
    assert r['matchType'] == 'EXPOSED_SECRET'
    assert r['severity'] == 'HIGH'
    assert r['metadata']['unsupportedProvider'] is True
    assert r['metadata']['verificationVerdict'] == 'unsupported-provider'


def test_unverified_still_demotes(tool):
    out = _run(tool._apply_secret_verification(
        [_exposed_row()], verifier=lambda url: {'verdict': 'unverified'},
    ))
    r = out[0]
    assert r['matchType'] == 'BRAND_MENTION'
    assert r['severity'] == 'LOW'
    assert r['metadata']['unverifiedSecretCandidate'] is True


def test_verified_promotes_to_high(tool):
    out = _run(tool._apply_secret_verification(
        [_exposed_row()], verifier=lambda url: {'verdict': 'verified'},
    ))
    r = out[0]
    assert r['matchType'] == 'EXPOSED_SECRET'
    assert r['severity'] == 'HIGH'
    assert r['riskScore'] >= 85


# ── P1.5 — on-demand full-cohort sweep ────────────────────────────────────────

def test_sweep_covers_multiple_cohorts_within_budget(tool):
    sweep = tool._build_sweep_queries(['lumenfield', 'acme'], 'lumenfield.test')
    assert len(sweep) <= tool._GH_SWEEP_MAX_UNITS
    joined = ' '.join(q for (_t, _e, q, _p) in sweep)
    # Dorks from DIFFERENT cohorts appear in one sweep (cohort-1 filename dork +
    # cohort-2 extension dork), which a single rotated cadence run cannot do.
    assert 'filename:.npmrc' in joined       # cohort 1
    assert 'extension:pem' in joined         # cohort 2


def test_sweep_reaches_budget_deferred_overflow_dork(tool):
    sweep = tool._build_sweep_queries(['lumenfield'], 'lumenfield.test')
    joined = ' '.join(q for (_t, _e, q, _p) in sweep)
    # `filename:.dockercfg` is a cohort-1 OVERFLOW dork sliced off a cadence run;
    # the sweep includes it.
    assert 'filename:.dockercfg' in joined


# ── P2.8 — budget-deferred dork telemetry ─────────────────────────────────────

def test_deferred_dorks_emit_telemetry(tool):
    tool._dork_coverage = []
    # Cohort 1 carries more dorks than _GH_MAX_QUERIES_PER_TERM → overflow deferred.
    tool._build_cohort_queries(['lumenfield'], 'lumenfield.test', 1)
    assert tool._dork_coverage, 'expected budget-deferred dork telemetry'
    note = tool._dork_coverage[0]
    assert note['cohort'] == 1
    assert note['reason'] == 'per_scan_budget'
    assert len(note['deferredDorks']) > 0


def test_sweep_defers_nothing(tool):
    tool._dork_coverage = []
    tool._build_sweep_queries(['lumenfield'], 'lumenfield.test')
    assert tool._dork_coverage == [], 'a full sweep should defer no dorks'


# ── P2.7 — the deferred/absent high-signal dorks are present in the cohorts ───

def test_new_high_signal_dorks_present(tool):
    all_dorks = [d for dorks in tool._GH_CODE_DORK_COHORTS.values() for d in dorks]
    for expected in [
        'filename:credentials', 'filename:settings.py', 'filename:.pgpass',
        'filename:.aws/credentials', 'filename:.dockercfg',
        'filename:serviceAccount.json', 'extension:cfg', 'extension:bak',
        'extension:pfx', 'extension:p12', 'extension:key',
        'filename:terraform.tfvars',
    ]:
        assert expected in all_dorks, f'{expected} missing from dork cohorts'


# ── #1477 — redacted exposed-secret evidence (agent-side masking) ─────────────
#
# Every literal here is FABRICATED and authenticates to nothing (detection
# fixtures, not secrets). The point of these locks is the raw-value invariant:
# the raw secret string must appear in NONE of the returned/persisted fields.

# A synthetic AWS-style access key id (regex family aws-access-key-id: AKIA +
# exactly 16 upper/digit chars = 20-char matched span). Fabricated, inert.
LONG_FAKE_SECRET = 'AKIAEXAMPLE0000FAKEK'


def test_secret_pattern_names_cover_every_pattern(tool):
    # A new _SECRET_PATTERNS entry without a name would report a bare index —
    # keep the two index-aligned.
    assert len(tool._SECRET_PATTERN_NAMES) == len(tool._SECRET_PATTERNS)


def test_match_secret_returns_detail(tool):
    match = tool._match_secret(f'AWS_ACCESS_KEY_ID={LONG_FAKE_SECRET}')
    assert match is not None
    assert match['detectorName'] == 'aws-access-key-id'
    assert match['value'] == LONG_FAKE_SECRET


def test_match_secret_high_entropy_path(tool):
    frag = '"api_key": "aK9fZ2qR7xL4mB8nV3cP6tW1yH5jD0sG"'
    match = tool._match_secret(frag)
    assert match is not None
    # The generic-assignment regex fires before the entropy path here.
    assert match['detectorName'] in {'generic-assignment', 'high-entropy'}


def test_exposed_secret_evidence_shape(tool):
    match = tool._match_secret(f'AWS_ACCESS_KEY_ID={LONG_FAKE_SECRET}')
    ev = tool._build_exposed_secret_evidence(match)
    assert set(ev) == {
        'maskedPreview', 'detectorName', 'secretType', 'length',
        'entropyBits', 'fingerprint',
    }
    assert ev['detectorName'] == 'aws-access-key-id'
    assert ev['length'] == len(LONG_FAKE_SECRET)
    # Masked preview reveals first 4 + last 2, masks the middle.
    assert ev['maskedPreview'].startswith(LONG_FAKE_SECRET[:4])
    assert ev['maskedPreview'].endswith(LONG_FAKE_SECRET[-2:])
    assert '•' in ev['maskedPreview']


def test_raw_value_invariant_evidence(tool):
    # The full raw secret string must appear in NONE of the returned fields.
    match = tool._match_secret(f'AWS_ACCESS_KEY_ID={LONG_FAKE_SECRET}')
    ev = tool._build_exposed_secret_evidence(match)
    for k, v in ev.items():
        if isinstance(v, str):
            assert LONG_FAKE_SECRET not in v, f'raw secret leaked into {k}'
    # The fingerprint is not the raw value and is fixed-length.
    assert ev['fingerprint'] != LONG_FAKE_SECRET
    assert len(ev['fingerprint']) == tool._SECRET_FINGERPRINT_LEN


def test_short_secret_masked_fully(tool):
    # A <12-char token must be masked FULLY — no reconstructable prefix/suffix.
    short = 'aB3xK9'  # 6 chars
    preview = tool._mask_secret_value(short)
    assert short[:4] not in preview
    assert short not in preview
    assert set(preview) == {'•'}


def test_low_entropy_secret_masked_fully(tool):
    # A long but low-entropy token (all-repeating) is masked fully — revealing
    # prefix/suffix of a low-entropy value would expose a reconstructable slice.
    low = 'aaaaaaaaaaaaaaaaaaaa'  # 20 chars, entropy 0
    preview = tool._mask_secret_value(low)
    assert set(preview) == {'•'}


def test_fingerprint_dedupe_same_secret_same_fp(tool):
    # Same synthetic secret in two different repos → same fingerprint (dedupe).
    fp1 = tool._secret_fingerprint(LONG_FAKE_SECRET)
    fp2 = tool._secret_fingerprint(LONG_FAKE_SECRET)
    assert fp1 == fp2
    # Two DIFFERENT secrets differ.
    other = 'AKIAEXAMPLE1111FAKEK'
    assert tool._secret_fingerprint(other) != fp1


def test_emit_github_match_attaches_exposed_secret(tool):
    row = tool._emit_github_match(
        source_name='GitHub - lumenfield-org/config',
        html_url='https://github.com/lumenfield-org/config/blob/HEAD/app.py',
        source_id='github-abc123',
        repo_full_name='lumenfield-org/config',
        fragment=f'AWS_ACCESS_KEY_ID={LONG_FAKE_SECRET}',
        search_term='lumenfield',
        domain='lumenfield.test',
        patterns=[{'value': 'lumenfield'}],
        path='app.py',
        sha='abc123',
    )
    assert row is not None
    assert row['matchType'] == 'EXPOSED_SECRET'
    ev = row['metadata']['exposedSecret']
    assert ev['detectorName'] == 'aws-access-key-id'
    # Raw-value invariant across the WHOLE emitted row (metadata + snippet + title).
    import json as _json
    blob = _json.dumps(row)
    assert LONG_FAKE_SECRET not in blob, 'raw secret leaked into emitted row'


def test_emit_github_match_no_secret_omits_evidence(tool):
    row = tool._emit_github_match(
        source_name='GitHub - lumenfield-org/docs',
        html_url='https://github.com/lumenfield-org/docs',
        source_id='github-def456',
        repo_full_name='lumenfield-org/docs',
        fragment='a helper library for lumenfield oauth flows',
        search_term='lumenfield',
        domain='lumenfield.test',
        patterns=[{'value': 'lumenfield'}],
    )
    assert row is not None
    assert row['matchType'] == 'BRAND_MENTION'
    assert 'exposedSecret' not in row['metadata']


def test_verification_verdict_folded_into_evidence(tool):
    row = tool._emit_github_match(
        source_name='GitHub - lumenfield-org/config',
        html_url='https://github.com/lumenfield-org/config',
        source_id='github-abc123',
        repo_full_name='lumenfield-org/config',
        fragment=f'AWS_ACCESS_KEY_ID={LONG_FAKE_SECRET}',
        search_term='lumenfield',
        domain='lumenfield.test',
        patterns=[{'value': 'lumenfield'}],
    )
    out = _run(tool._apply_secret_verification(
        [row], verifier=lambda url: {'verdict': 'unsupported-provider'},
    ))
    ev = out[0]['metadata']['exposedSecret']
    assert ev['verificationVerdict'] == 'unsupported-provider'

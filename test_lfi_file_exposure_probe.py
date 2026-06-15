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


if __name__ == "__main__":
    unittest.main()

import unittest

from tools.cve_runtime_probe import (
    CveRuntimeProbeTool,
    _build_cve_runtime_coverage,
    _detect_angularjs_runtime_context,
    _collect_cve_records,
    _detect_bootstrap_xss_context,
    _detect_dompurify_runtime_context,
    _normalize_angularjs_context_finding,
    _normalize_bootstrap_context_finding,
    _normalize_dompurify_context_finding,
)


class CveRuntimeProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_standard_mode_skips_active_runtime_validation(self):
        tool = CveRuntimeProbeTool()

        result = await tool.execute(
            {
                "target": "https://example.test",
                "cves": ["CVE-2025-30218"],
                "aggressive": False,
            }
        )

        self.assertTrue(result["success"])
        self.assertTrue(result["skipped"])
        self.assertEqual(result["reason"], "AGGRESSIVE_REQUIRED")
        self.assertEqual(result["summary"]["findings"], 0)

    def test_collects_cves_from_retirejs_aggregate_findings(self):
        records = _collect_cve_records(
            {
                "libraries": [
                    {
                        "name": "nextjs",
                        "version": "14.2.25",
                        "scriptUrl": "https://example.test/_next/static/chunks/main.js",
                        "cves": ["CVE-2025-30218"],
                    }
                ],
                "findings": [
                    {
                        "matched-at": "https://example.test/_next/static/chunks/main.js",
                        "info": {
                            "cve": ["CVE-2025-30218", "CVE-2025-29927"],
                            "reference": ["https://github.com/advisories/GHSA-223j-4rm8-mrmf"],
                        },
                        "evidence": {
                            "scriptUrl": "https://example.test/_next/static/chunks/main.js",
                            "cveIds": ["CVE-2025-30218", "CVE-2025-29927"],
                        },
                    },
                    {
                        "matched-at": "https://example.test/assets/bootstrap.min.js",
                        "info": {
                            "name": "Vulnerable JavaScript dependency: bootstrap@3.4.1 (2 CVEs)",
                            "cve": ["CVE-2024-6485", "CVE-2025-1647"],
                            "reference": ["https://github.com/advisories/GHSA-vc8w-jr9v-vj7f"],
                        },
                        "evidence": {
                            "scriptUrl": "https://example.test/assets/bootstrap.min.js",
                            "cveIds": ["CVE-2024-6485", "CVE-2025-1647"],
                        },
                    }
                ],
            }
        )

        self.assertIn("CVE-2025-30218", records)
        self.assertIn("CVE-2025-29927", records)
        self.assertEqual(records["CVE-2025-30218"]["packages"][0]["name"], "nextjs")
        self.assertIn(
            "https://example.test/_next/static/chunks/main.js",
            records["CVE-2025-29927"]["scripts"],
        )
        self.assertEqual(records["CVE-2024-6485"]["packages"][0]["name"], "bootstrap")
        self.assertEqual(records["CVE-2024-6485"]["packages"][0]["version"], "3.4.1")

    def test_bootstrap_context_probe_requires_strong_sink(self):
        cve_records = {
            "CVE-2024-6485": {
                "cve": "CVE-2024-6485",
                "packages": [{"name": "bootstrap", "version": "3.4.1"}],
                "scripts": ["https://example.test/assets/bootstrap.min.js"],
                "references": [],
                "advisories": [],
                "summaries": [],
            }
        }

        weak_context = _detect_bootstrap_xss_context(
            target="https://example.test/",
            cve_ids=["CVE-2024-6485"],
            cve_records=cve_records,
            pages=[
                {
                    "url": "https://example.test/",
                    "status": 200,
                    "text": '<button data-toggle="popover" data-content="Static help">Help</button>',
                }
            ],
            scripts=[
                {
                    "url": "https://example.test/assets/bootstrap.min.js",
                    "status": 200,
                    "text": "/*! Bootstrap v3.4.1 */ $.fn.tooltip=function(){}; $.fn.popover=function(){};",
                }
            ],
            reflection_proofs=[],
        )
        self.assertFalse(weak_context["findingCandidate"])

        strong_context = _detect_bootstrap_xss_context(
            target="https://example.test/",
            cve_ids=["CVE-2024-6485"],
            cve_records=cve_records,
            pages=[
                {
                    "url": "https://example.test/profile",
                    "status": 200,
                    "text": '<button data-toggle="popover" data-html="true" data-content="Profile">Help</button>',
                }
            ],
            scripts=[
                {
                    "url": "https://example.test/assets/bootstrap.min.js",
                    "status": 200,
                    "text": "/*! Bootstrap v3.4.1 */ $.fn.tooltip=function(){}; $.fn.popover=function(){};",
                }
            ],
            reflection_proofs=[],
        )
        self.assertTrue(strong_context["findingCandidate"])
        self.assertTrue(strong_context["runtimeContextValidated"])
        self.assertFalse(strong_context["runtimeExploitValidated"])

    def test_bootstrap_reflection_proof_upgrades_runtime_validation(self):
        cve_records = {
            "CVE-2024-6485": {
                "cve": "CVE-2024-6485",
                "packages": [{"name": "bootstrap", "version": "3.4.1"}],
                "scripts": ["https://example.test/assets/bootstrap.min.js"],
                "references": ["https://github.com/advisories/GHSA-vc8w-jr9v-vj7f"],
                "advisories": [],
                "summaries": [],
            }
        }
        context = _detect_bootstrap_xss_context(
            target="https://example.test/",
            cve_ids=["CVE-2024-6485"],
            cve_records=cve_records,
            pages=[],
            scripts=[
                {
                    "url": "https://example.test/assets/bootstrap.min.js",
                    "status": 200,
                    "text": "/*! Bootstrap v3.4.1 */ $.fn.tooltip=function(){}; $.fn.popover=function(){};",
                }
            ],
            reflection_proofs=[
                {
                    "url": "https://example.test/?q=xasm_bootstrap_probe_7d6f8c",
                    "status": 200,
                    "reflected": True,
                    "unsafeBootstrapContext": True,
                    "request": "GET /?q=xasm_bootstrap_probe_7d6f8c HTTP/1.1\nHost: example.test",
                    "responseExcerpt": '<button data-toggle="popover" data-html="true">xasm_bootstrap_probe_7d6f8c</button>',
                }
            ],
        )
        finding = _normalize_bootstrap_context_finding(
            target="https://example.test/",
            cve_ids=["CVE-2024-6485"],
            cve_records=cve_records,
            context=context,
            public_exploit_intel={},
        )

        self.assertTrue(context["runtimeExploitValidated"])
        self.assertEqual(finding["info"]["severity"], "high")
        self.assertTrue(finding["evidence"]["runtimeExploitValidated"])
        self.assertIn("GET /?q=xasm_bootstrap_probe_7d6f8c", finding["evidence"]["request"])
        self.assertIn("GET /?q=xasm_bootstrap_probe_7d6f8c", finding["request"])
        self.assertIn("xasm_bootstrap_probe_7d6f8c", finding["response"])

    def test_angularjs_context_probe_detects_strong_runtime_surface(self):
        cve_records = {
            "CVE-2019-10768": {
                "cve": "CVE-2019-10768",
                "packages": [{"name": "angularjs", "version": "1.5.11"}],
                "scripts": ["https://example.test/assets/angular.min.js"],
                "references": [],
                "advisories": [],
                "summaries": [],
            }
        }

        context = _detect_angularjs_runtime_context(
            target="https://example.test/",
            cve_ids=["CVE-2019-10768"],
            cve_records=cve_records,
            pages=[
                {
                    "url": "https://example.test/profile",
                    "status": 200,
                    "text": '<main ng-app="app"><div ng-bind-html="profile.bio"></div></main>',
                }
            ],
            scripts=[
                {
                    "url": "https://example.test/assets/angular.min.js",
                    "status": 200,
                    "text": "/* AngularJS v1.5.11 */ angular.module('app',[]).controller('Profile',function($sce){ return $sce.trustAsHtml(x); });",
                }
            ],
            reflection_proofs=[],
        )
        finding = _normalize_angularjs_context_finding(
            target="https://example.test/",
            cve_ids=["CVE-2019-10768"],
            cve_records=cve_records,
            context=context,
            public_exploit_intel={},
        )

        self.assertTrue(context["findingCandidate"])
        self.assertTrue(context["runtimeContextValidated"])
        self.assertFalse(context["runtimeExploitValidated"])
        self.assertEqual(finding["info"]["severity"], "medium")
        self.assertTrue(finding["evidence"]["runtimeContextValidated"])
        self.assertIn("angularjs@1.5.11", finding["info"]["name"])
        self.assertIn("GET /profile", finding["request"])
        self.assertIn("ng-bind-html", finding["response"])

    def test_dompurify_context_probe_detects_runtime_sanitizer_surface(self):
        cve_records = {
            "CVE-2024-47875": {
                "cve": "CVE-2024-47875",
                "packages": [{"name": "DOMPurify", "version": "2.3.3"}],
                "scripts": ["https://example.test/api/docs/swagger-ui-bundle.js"],
                "references": ["https://github.com/advisories/GHSA-gx9m-whjm-85jf"],
                "advisories": [],
                "summaries": [],
            }
        }

        context = _detect_dompurify_runtime_context(
            target="https://example.test/",
            cve_ids=["CVE-2024-47875"],
            cve_records=cve_records,
            pages=[
                {
                    "url": "https://example.test/docs",
                    "status": 200,
                    "text": '<div id="swagger-ui"></div><script src="/api/docs/swagger-ui-bundle.js"></script>',
                }
            ],
            scripts=[
                {
                    "url": "https://example.test/api/docs/swagger-ui-bundle.js",
                    "status": 200,
                    "text": "/*! DOMPurify 2.3.3 */ const clean = DOMPurify.sanitize(markdownHtml, {ADD_ATTR:['target']}); root.innerHTML = clean;",
                }
            ],
        )
        finding = _normalize_dompurify_context_finding(
            target="https://example.test/",
            cve_ids=["CVE-2024-47875"],
            cve_records=cve_records,
            context=context,
            public_exploit_intel={},
        )

        self.assertTrue(context["findingCandidate"])
        self.assertTrue(context["runtimeContextValidated"])
        self.assertFalse(context["runtimeExploitValidated"])
        self.assertEqual(finding["info"]["severity"], "medium")
        self.assertTrue(finding["evidence"]["runtimeContextValidated"])
        self.assertIn("GET /api/docs/swagger-ui-bundle.js", finding["evidence"]["request"])
        self.assertIn("DOMPurify.sanitize", finding["evidence"]["response"])
        self.assertIn("GET /api/docs/swagger-ui-bundle.js", finding["request"])
        self.assertIn("DOMPurify.sanitize", finding["response"])
        self.assertIn("DOMPurify@2.3.3", finding["matchedContent"])

    def test_runtime_coverage_explains_template_only_gap(self):
        coverage = _build_cve_runtime_coverage(
            cve_ids=["CVE-2025-30218"],
            cve_records={
                "CVE-2025-30218": {
                    "cve": "CVE-2025-30218",
                    "packages": [{"name": "nextjs", "version": "14.2.25"}],
                    "scripts": ["https://example.test/_next/static/chunks/main.js"],
                    "references": [],
                    "advisories": [],
                    "summaries": [],
                }
            },
            template_results=[
                {
                    "cve": "CVE-2025-30218",
                    "status": "template_unavailable",
                    "nucleiAvailable": True,
                }
            ],
            contextual_results=[],
            public_exploit_intel={
                "CVE-2025-30218": {
                    "references": [{"url": "https://example.test/advisory"}],
                    "exploitMaturity": "public_references_only",
                }
            },
        )

        self.assertEqual(coverage[0]["status"], "not_runtime_validated")
        self.assertEqual(coverage[0]["templateStatus"], "unavailable")
        self.assertIn("public exploit intelligence", coverage[0]["reason"])


if __name__ == "__main__":
    unittest.main()

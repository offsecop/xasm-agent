"""
git:source_disclosure_scanner — exposed `.git` history reconstruction + secret recovery.

Scope is deliberately the part nothing else on the platform does. The "the .git directory
is exposed" SIGNAL is already owned by nuclei's `http/exposures/configs/git-config` template
and the dirsearch wordlist, so this tool does NOT emit an exposure finding — it is their deep
complement. GET-only (read-only, no aggressive/engagement gate needed):

1. Probe `/.git/HEAD`, `/.git/config`, `/.git/index` and CONTENT-VALIDATE each (a `ref:`/
   40-hex HEAD, a `[core]` config, a `DIRC`-magic index) so an SPA catch-all that 200s every
   path does not trigger a pointless reconstruction. This only GATES stage 2; no finding here.

2. Reconstruct the repo over "dumb HTTP" — resolve HEAD, read every commit SHA from
   `refs/heads/*`, `packed-refs`, and the `logs/HEAD` reflog (which still lists commits that
   were `reset`/`revert`-ed away), then BFS the loose object store (`objects/<2>/<38>`,
   zlib-inflated) walking commit -> tree -> blob. Commit messages and blob contents are scanned
   for hardcoded secret shapes. ONLY recovered secrets are reported, REDACTED (label + masked
   preview + sha256), never in clear — each carrying the exposure context as evidence.

Mirrors the Nuclei-shaped finding envelope so the backend reuses `processNucleiOutput`
(ingestion signature `VCS_EXPOSURE`). Source TTP: HTB VariaType #1 (corpus
research/htb-writeups/medium/VariaType.md); shares secret patterns with `origami:client_secret_scan`
(which scans live JS/HTML, a different surface).
"""

import asyncio
import hashlib
import re
import zlib
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import aiohttp

from plugin_interface import ToolPlugin


# .git files that, when content-valid, confirm an exposed repository.
GIT_INDICATORS = ["HEAD", "config", "index"]
# Extra ref/log sources mined for commit SHAs during reconstruction.
GIT_REF_SOURCES = ["packed-refs", "logs/HEAD", "ORIG_HEAD", "FETCH_HEAD"]

SHA1_RE = re.compile(rb"\b[0-9a-f]{40}\b")
HEAD_REF_RE = re.compile(r"^ref:\s*(\S+)", re.IGNORECASE)
HTML_MARKERS = ("<!doctype html", "<html", "<head", "<body", "<title")

# Hardcoded-secret detectors. group(1) (when present) is the sensitive value; otherwise the
# whole match is treated as the secret. Tuned to fire on real assignments, not prose.
SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("aws_access_key_id", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+]{40})")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("slack_token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,})\b")),
    ("api_key", re.compile(r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b\s*[=:]\s*['\"]?([^\s'\"#;]{8,})")),
    ("password", re.compile(r"(?i)\b(?:password|passwd|pwd|db[_-]?pass(?:word)?)\b\s*[=:]\s*['\"]?([^\s'\"#;]{4,})")),
]
# Obvious non-secret placeholders to suppress.
SECRET_PLACEHOLDERS = {
    "password", "changeme", "example", "your_password", "xxxxxxxx", "password123",
    "none", "null", "true", "false", "redacted", "secret", "<password>", "...",
}
# Keyword-less credential pairs (e.g. PHP `'gitbot' => 'G1tB0t_Acc3ss_2025!'`, YAML/JSON
# `key: "val"`, ctor `Foo("val")`). The captured value is complexity-gated by _looks_secret
# so ordinary string constants (paths, mime types, words) do not fire.
ASSIGNED_VALUE_RE = re.compile(r"""(?:=>|[:=]|\()\s*['"]([^'"\n]{8,64})['"]""")


class GitSourceDisclosureScannerTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "git:source_disclosure_scanner"

    @property
    def description(self) -> str:
        return (
            "Reconstructs an HTTP-exposed .git repository over dumb HTTP and recovers hardcoded "
            "secrets from commit history — including reset/reverted commits via the reflog. "
            "The exposure signal itself is owned by nuclei's git-config template / dirsearch; "
            "this is their deep complement. Read-only GET probes; secrets reported redacted."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "url": {"type": "string"},
                "enabled": {"type": "boolean", "default": True},
                "reconstruct": {"type": "boolean", "default": True},
                "maxObjects": {"type": "integer", "default": 400},
                "maxBytes": {"type": "integer", "default": 262144},
                "maxRequests": {"type": "integer", "default": 600},
                "timeoutSeconds": {"type": "integer", "default": 15},
                "headers": {"type": "object"},
                "cookie": {"type": "string"},
            },
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "vuln-scan",
            "phase": 3,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["httpx:", "katana:", "dirsearch:", "nuclei:"],
            "chainable_before": ["decision:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        if parameters.get("enabled") is False:
            return {"success": True, "skipped": True, "tool": self.name, "findings": []}

        raw_target = parameters.get("target") or parameters.get("url") or ""
        origin = self._origin(raw_target)
        if not origin:
            return {"success": False, "error": f"target must be an http(s) URL: {raw_target!r}"}

        timeout_s = max(3, min(int(parameters.get("timeoutSeconds") or 15), 120))
        self._max_objects = max(1, min(int(parameters.get("maxObjects") or 400), 5000))
        self._max_bytes = max(1024, min(int(parameters.get("maxBytes") or 262144), 4_000_000))
        self._max_requests = max(3, min(int(parameters.get("maxRequests") or 600), 8000))
        self._reqs = 0
        reconstruct = bool(parameters.get("reconstruct", True))

        headers = {"User-Agent": "xASM-git-source-disclosure-scanner/1.0", "Accept": "*/*"}
        extra = parameters.get("headers")
        if isinstance(extra, dict):
            headers.update({str(k): str(v) for k, v in extra.items()})
        if parameters.get("cookie"):
            headers["Cookie"] = str(parameters["cookie"])

        git_base = f"{origin}/.git/"
        findings: List[Dict[str, Any]] = []
        agent = parameters.get("_agent")

        connector = aiohttp.TCPConnector(ssl=False, limit=8)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout_s),
            headers=headers,
        ) as session:
            self._session = session
            # Stage 1 — content-validated exposure probe.
            indicators: Dict[str, Dict[str, Any]] = {}
            for name in GIT_INDICATORS:
                status, body = await self._get(git_base + name)
                valid = self._validate_indicator(name, status, body)
                indicators[name] = {"status": status, "valid": valid, "body": body}
                if agent:
                    agent.report_progress("Probing .git indicators", git_base + name, len(indicators), len(GIT_INDICATORS))

            present = [n for n, v in indicators.items() if v["valid"]]
            if not present:
                return {
                    "success": True,
                    "tool": self.name,
                    "target": origin,
                    "exposed": False,
                    "findings": [],
                    "summary": {"indicatorsProbed": len(GIT_INDICATORS), "indicatorsValid": 0, "secrets": 0},
                }

            config_text = indicators["config"]["body"].decode("utf-8", "replace") if indicators["config"]["valid"] else ""
            branch = self._head_branch(indicators["HEAD"]["body"]) if indicators["HEAD"]["valid"] else None
            committer = re.search(r"(?im)^\s*email\s*=\s*(\S+)", config_text)
            # NOTE: "the .git directory is exposed" is INTENTIONALLY not emitted as a finding —
            # nuclei's http/exposures/configs/git-config template and the dirsearch wordlist
            # already own that detection. This tool's unique value (and its only findings) is
            # reconstructing the repo over dumb HTTP and recovering secrets from commit history,
            # including reset/reverted commits via the reflog (#324 de-duplication decision).
            exposure_context = {
                "indicators": present,
                "branch": branch,
                "committerEmail": committer.group(1) if committer else None,
            }

            # Reconstruct + mine history for secrets (the genuinely new capability).
            secrets: List[Dict[str, Any]] = []
            commit_count = 0
            if reconstruct:
                commits = await self._collect_commits(git_base, branch, agent)
                commit_count = len(commits)
                secrets = await self._mine_secrets(git_base, commits, agent)
                for s in secrets:
                    findings.append(self._secret_finding(git_base, s, exposure_context))

        raw_lines = [f"[{f['info']['severity'].upper()}] {f['info']['name']} - {f['matched-at']}" for f in findings]
        return {
            "success": True,
            "tool": self.name,
            "target": origin,
            "exposed": True,
            "exposureContext": exposure_context,
            # exposure DETECTION is owned by these existing capabilities, not this tool:
            "exposureDetectionOwnedBy": "nuclei:git-config + dirsearch",
            "findings": findings,
            "total_findings": len(findings),
            "rawOutput": "\n".join(raw_lines),
            "summary": {
                "indicatorsProbed": len(GIT_INDICATORS),
                "indicatorsValid": len(present),
                "commitsRecovered": commit_count,
                "secrets": len(findings),
                "requests": self._reqs,
            },
        }

    # ----- HTTP -----
    async def _get(self, url: str) -> Tuple[Optional[int], bytes]:
        if self._reqs >= self._max_requests:
            return None, b""
        self._reqs += 1
        try:
            async with self._session.get(url, allow_redirects=False) as resp:
                body = await resp.content.read(self._max_bytes + 1)
                return resp.status, body[: self._max_bytes]
        except Exception:
            return None, b""

    # ----- exposure validation -----
    def _validate_indicator(self, name: str, status: Optional[int], body: bytes) -> bool:
        if status != 200 or not body:
            return False
        head = body[:512].lstrip().lower()
        if any(m in head.decode("utf-8", "replace") for m in HTML_MARKERS):
            return False  # SPA / error page catch-all, not a real .git file
        if name == "HEAD":
            text = body.strip()
            return bool(HEAD_REF_RE.match(text.decode("utf-8", "replace"))) or bool(re.fullmatch(rb"[0-9a-f]{40}", text))
        if name == "config":
            return b"[core]" in body
        if name == "index":
            return body[:4] == b"DIRC"
        return False

    def _head_branch(self, head_body: bytes) -> Optional[str]:
        m = HEAD_REF_RE.match(head_body.strip().decode("utf-8", "replace"))
        if m:
            return m.group(1)  # e.g. refs/heads/master
        return None

    # ----- reconstruction -----
    async def _collect_commits(self, git_base: str, branch: Optional[str], agent) -> Dict[str, Dict[str, Any]]:
        """Seed commit SHAs from refs + reflog (incl. reset-away commits), then walk parents."""
        seeds: set = set()
        ref_paths = []
        if branch:
            ref_paths.append(branch.lstrip("/"))
        ref_paths += ["refs/heads/master", "refs/heads/main"]
        for rp in ref_paths:
            _, body = await self._get(git_base + rp)
            for m in SHA1_RE.findall(body):
                seeds.add(m.decode())
        for src in GIT_REF_SOURCES:
            _, body = await self._get(git_base + src)
            for m in SHA1_RE.findall(body):
                seeds.add(m.decode())

        commits: Dict[str, Dict[str, Any]] = {}
        queue = list(seeds)
        visited: set = set()
        while queue and len(commits) < self._max_objects:
            sha = queue.pop(0)
            if sha in visited:
                continue
            visited.add(sha)
            obj = await self._object(git_base, sha)
            if not obj or obj[0] != "commit":
                continue
            parsed = self._parse_commit(obj[1])
            commits[sha] = parsed
            for parent in parsed["parents"]:
                if parent not in visited:
                    queue.append(parent)
            if agent:
                agent.report_progress("Recovering commits", sha[:8], len(commits), self._max_objects)
        return commits

    async def _object(self, git_base: str, sha: str) -> Optional[Tuple[str, bytes]]:
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            return None
        status, body = await self._get(f"{git_base}objects/{sha[:2]}/{sha[2:]}")
        if status != 200 or not body:
            return None  # packed-only or missing; gracefully skip
        try:
            data = zlib.decompress(body)
        except Exception:
            return None
        nul = data.find(b"\x00")
        if nul < 0:
            return None
        header = data[:nul].split(b" ", 1)
        if len(header) != 2:
            return None
        return header[0].decode("ascii", "replace"), data[nul + 1 :]

    def _parse_commit(self, payload: bytes) -> Dict[str, Any]:
        text = payload.decode("utf-8", "replace")
        tree = None
        parents: List[str] = []
        lines = text.split("\n")
        msg_start = 0
        for i, line in enumerate(lines):
            if line.startswith("tree "):
                tree = line[5:].strip()
            elif line.startswith("parent "):
                parents.append(line[7:].strip())
            elif line == "":
                msg_start = i + 1
                break
        return {"tree": tree, "parents": parents, "message": "\n".join(lines[msg_start:]).strip()}

    def _parse_tree(self, payload: bytes) -> List[Tuple[str, str]]:
        """Return [(name, sha_hex)] for a tree object."""
        entries: List[Tuple[str, str]] = []
        i = 0
        n = len(payload)
        while i < n:
            sp = payload.find(b" ", i)
            if sp < 0:
                break
            nul = payload.find(b"\x00", sp)
            if nul < 0 or nul + 21 > n:
                break
            name = payload[sp + 1 : nul].decode("utf-8", "replace")
            sha_hex = payload[nul + 1 : nul + 21].hex()
            entries.append((name, sha_hex))
            i = nul + 21
        return entries

    async def _mine_secrets(self, git_base: str, commits: Dict[str, Dict[str, Any]], agent) -> List[Dict[str, Any]]:
        found: Dict[str, Dict[str, Any]] = {}
        blob_cache: Dict[str, Optional[bytes]] = {}
        seen_values: set = set()

        def record(label: str, value: str, source: str, commit_sha: str, message: str):
            # A value already caught by a specific detector (aws/api_key/...) should not
            # also be reported under the generic hardcoded_credential label.
            if label == "hardcoded_credential" and value in seen_values:
                return
            seen_values.add(value)
            key = f"{label}|{value}|{source.split('@')[0].strip()}"
            if key in found:
                return
            found[key] = {
                "label": label,
                "masked": self._mask(value),
                "sha256": hashlib.sha256(value.encode("utf-8", "replace")).hexdigest(),
                "source": source,
                "commit": commit_sha[:10],
                "commitMessage": message[:120],
            }

        for sha, c in commits.items():
            # commit messages occasionally carry secrets too
            for label, value in self._scan(c["message"]):
                record(label, value, f"commit-message @ {sha[:8]}", sha, c["message"])
            if not c["tree"]:
                continue
            for path, blob_sha in await self._walk_tree(git_base, c["tree"], "", set()):
                if blob_sha not in blob_cache:
                    obj = await self._object(git_base, blob_sha)
                    blob_cache[blob_sha] = obj[1] if (obj and obj[0] == "blob") else None
                content = blob_cache[blob_sha]
                if not content:
                    continue
                for label, value in self._scan(content.decode("utf-8", "replace")):
                    record(label, value, f"{path} @ {sha[:8]}", sha, c["message"])
            if agent:
                agent.report_progress("Mining history for secrets", sha[:8], len(found), self._max_objects)
        return list(found.values())

    async def _walk_tree(self, git_base: str, tree_sha: str, prefix: str, seen: set) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        if tree_sha in seen or len(seen) >= self._max_objects:
            return out
        seen.add(tree_sha)
        obj = await self._object(git_base, tree_sha)
        if not obj or obj[0] != "tree":
            return out
        for name, sha in self._parse_tree(obj[1]):
            path = f"{prefix}{name}"
            child = await self._object(git_base, sha)
            if child and child[0] == "tree":
                out.extend(await self._walk_tree(git_base, sha, path + "/", seen))
            else:
                out.append((path, sha))
        return out

    def _scan(self, text: str) -> List[Tuple[str, str]]:
        hits: List[Tuple[str, str]] = []
        if not text:
            return hits
        for label, pattern in SECRET_PATTERNS:
            for m in pattern.finditer(text):
                value = m.group(1) if m.groups() else m.group(0)
                value = value.strip().strip("'\"")
                if not value or value.lower() in SECRET_PLACEHOLDERS or len(value) < 4:
                    continue
                hits.append((label, value))
        # Keyword-less credential pairs (assigned string literals with password-like complexity).
        for m in ASSIGNED_VALUE_RE.finditer(text):
            value = m.group(1).strip()
            if self._looks_secret(value):
                hits.append(("hardcoded_credential", value))
        return hits

    def _looks_secret(self, v: str) -> bool:
        """Complexity gate so only credential-shaped literals fire (keeps FPs off paths/words/mime)."""
        if not (8 <= len(v) <= 64) or v.lower() in SECRET_PLACEHOLDERS:
            return False
        if any(c in v for c in (" ", "/", "\\")) or v.startswith(("http://", "https://", "www.")):
            return False
        classes = sum([
            bool(re.search(r"[a-z]", v)),
            bool(re.search(r"[A-Z]", v)),
            bool(re.search(r"\d", v)),
            bool(re.search(r"[^A-Za-z0-9]", v)),
        ])
        return classes >= 3 and bool(re.search(r"\d", v)) and bool(re.search(r"[A-Za-z]", v))

    def _mask(self, value: str) -> str:
        if len(value) <= 4:
            return "*" * len(value)
        return f"{value[:2]}{'*' * (min(len(value), 12) - 4)}{value[-2:]} (len={len(value)})"

    # ----- findings (Nuclei-shaped) -----
    # NOTE: there is deliberately NO exposure finding — nuclei's git-config exposure
    # template + the dirsearch wordlist already own ".git is exposed". This tool only
    # reports secrets recovered from the reconstructed history (the new capability).
    def _secret_finding(self, git_base: str, s: Dict[str, Any], exposure: Dict[str, Any]) -> Dict[str, Any]:
        # Distinct template-id per secret type so the ingestion VCS_EXPOSURE signature
        # (assetId:port:VCS_EXPOSURE:templateId:path) does not collapse different secrets.
        extracted = [
            f"type:{s['label']}",
            f"value:{s['masked']}",
            f"sha256:{s['sha256']}",
            f"source:{s['source']}",
            f"commit:{s['commit']}",
            f"exposedGit:{git_base}",
        ]
        if exposure.get("branch"):
            extracted.append(f"branch:{exposure['branch']}")
        if exposure.get("committerEmail"):
            extracted.append(f"committerEmail:{exposure['committerEmail']}")
        return self._finding(
            template_id=f"xasm-git-history-secret-{s['label']}",
            name=f"Hardcoded {s['label']} Recovered from Exposed Git History",
            severity="critical",
            matched_at=f"{git_base}",
            description=(
                f"A hardcoded {s['label']} was recovered by reconstructing the exposed .git "
                f"repository over dumb HTTP and scanning its commit history ({s['source']}; "
                f"commit {s['commit']} \"{s['commitMessage']}\"). Secrets committed to history "
                "remain recoverable even after being removed in a later commit. (The .git "
                "exposure itself is detected separately by nuclei's git-config template / dirsearch.)"
            ),
            remediation="Rotate the exposed credential immediately and purge it from git history; block .git over HTTP.",
            matcher_name=f"git-history-secret:{s['label']}",
            extracted=extracted,
        )

    def _finding(self, *, template_id, name, severity, matched_at, description, remediation, matcher_name, extracted) -> Dict[str, Any]:
        return {
            "template-id": template_id,
            "templateID": template_id,
            "matched-at": matched_at,
            "matched": matched_at,
            "host": matched_at,
            "matcher-name": matcher_name,
            "extracted-results": [e for e in extracted if e],
            "info": {"name": name, "severity": severity, "description": description, "remediation": remediation},
        }

    def _origin(self, raw: str) -> Optional[str]:
        raw = str(raw or "").strip()
        if not raw:
            return None
        if "://" not in raw:
            raw = "http://" + raw
        p = urlparse(raw)
        if p.scheme not in {"http", "https"} or not p.netloc:
            return None
        return urlunparse((p.scheme, p.netloc, "", "", "", ""))


def get_tool():
    return GitSourceDisclosureScannerTool()

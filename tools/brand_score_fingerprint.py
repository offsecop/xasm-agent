"""
Brand Score Fingerprint Tool
Scores a typosquat target URL against a known brand fingerprint
by comparing colors, logos, fonts, text, layout, and favicon.
"""

import json
import math
import re
from collections import Counter
from plugin_interface import ToolPlugin
from typing import Dict, Any, List, Optional, Set


def _color_frequency_vector(colors: List[Dict[str, Any]]) -> Dict[str, float]:
    """Build a color->frequency dict from dominant color list."""
    return {c['hex']: c.get('frequency', 0) for c in colors}


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
    return (matches / total) * 100 if total > 0 else 50.0


def _parse_color_hex(color_str: str) -> Optional[str]:
    """Convert an rgb/rgba CSS color string to hex."""
    if not color_str:
        return None
    m = re.match(r'rgba?\((\d+),\s*(\d+),\s*(\d+)', color_str)
    if m:
        r, g, b = int(m.group(1)), int(m.group(2)), int(m.group(3))
        return f'#{r:02x}{g:02x}{b:02x}'
    if color_str.startswith('#'):
        return color_str.lower()
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

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=['--no-sandbox'])
                context = await browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                )
                page = await context.new_page()
                target_identity = await extract_page_identity(page, target_url)
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
        target_colors_raw = target_identity.get('colors', [])
        target_hex_colors: list = []
        for c in target_colors_raw:
            hx = _parse_color_hex(c)
            if hx and hx != '#000000' and hx != '#ffffff':
                target_hex_colors.append(hx)

        target_color_counter = Counter(target_hex_colors)
        total_t = sum(target_color_counter.values()) or 1
        target_color_freq = {h: c / total_t for h, c in target_color_counter.items()}

        brand_color_freq = _color_frequency_vector(fingerprint.get('dominantColors', []))

        # 1. Color score (weight 0.25)
        color_score = _cosine_similarity(brand_color_freq, target_color_freq)

        # 2. Logo score (weight 0.25)
        brand_logos = fingerprint.get('logoHashes', [])
        target_logos = target_identity.get('logos', [])
        logo_score = 0.0
        if brand_logos and target_logos:
            best_sim = 0.0
            for bl in brand_logos:
                for tl in target_logos:
                    sim = _hamming_distance_normalized(bl['hash'], tl['hash'])
                    if sim > best_sim:
                        best_sim = sim
            logo_score = best_sim
        elif not brand_logos and not target_logos:
            logo_score = 50.0  # Neutral if neither has logos

        # 3. Font score (weight 0.10)
        brand_fonts = set(f.lower() for f in fingerprint.get('fontFamilies', []))
        target_fonts = set(f.lower() for f in target_identity.get('fonts', []))
        font_score = _jaccard_similarity(brand_fonts, target_fonts)

        # 4. Text score (weight 0.20)
        brand_texts = fingerprint.get('textPatterns', [])
        target_texts = target_identity.get('texts', [])
        text_score = _ngram_overlap(brand_texts, target_texts)

        # 5. Layout score (weight 0.10)
        brand_layout = fingerprint.get('layoutPatterns', {})
        target_layout = target_identity.get('layout', {})
        layout_score_val = _layout_score(brand_layout, target_layout)

        # 6. Favicon score (weight 0.10)
        brand_favicon = fingerprint.get('faviconHash')
        target_favicon = target_identity.get('favicon')
        favicon_score = 0.0
        if brand_favicon and target_favicon:
            favicon_score = _hamming_distance_normalized(brand_favicon, target_favicon)
        elif not brand_favicon and not target_favicon:
            favicon_score = 50.0

        # Composite score
        composite = (
            0.25 * color_score +
            0.25 * logo_score +
            0.10 * font_score +
            0.20 * text_score +
            0.10 * layout_score_val +
            0.10 * favicon_score
        )

        composite = round(composite, 1)
        color_score = round(color_score, 1)
        logo_score = round(logo_score, 1)
        font_score = round(font_score, 1)
        text_score = round(text_score, 1)
        layout_score_val = round(layout_score_val, 1)
        favicon_score = round(favicon_score, 1)

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
                f"Layout: {layout_score_val} | Favicon: {favicon_score}"
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
                'brandMonitorId': brand_monitor_id,
                'typosquatDomainId': typosquat_domain_id,
                'targetUrl': target_url,
                'tool': 'brand',
                'scan_type': 'score_fingerprint',
            }
        }


def get_tool():
    return BrandScoreFingerprintTool()

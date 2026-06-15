"""
Brand Fingerprint Identity Tool
Extracts brand visual identity (colors, logos, fonts, layout, text patterns)
from reference URLs to build a brand fingerprint for typosquat comparison.
"""

import asyncio
import io
import json
import os
import re
from collections import Counter
from plugin_interface import ToolPlugin
from typing import Dict, Any, List, Optional


async def extract_page_identity(page, url: str) -> Dict[str, Any]:
    """Extract visual identity data from a single page using Playwright.

    This is a shared helper used by both the fingerprint and scoring tools.
    The caller is responsible for creating and closing the browser.
    ``page`` must be an already-created Playwright page object.

    Returns a dict with keys: colors, logos, fonts, layout, texts, favicon, error.
    """
    result: Dict[str, Any] = {
        'colors': [],
        'logos': [],
        'fonts': [],
        'layout': {},
        'texts': [],
        'favicon': None,
        'error': None,
    }

    try:
        response = await page.goto(url, wait_until='networkidle', timeout=30000)
        if not response:
            result['error'] = f'No response from {url}'
            return result
    except Exception as e:
        result['error'] = f'Navigation failed for {url}: {str(e)[:200]}'
        return result

    try:
        # Extract computed CSS from key elements
        css_data = await page.evaluate("""() => {
            const selectors = 'body, h1, h2, h3, nav, header, footer, button, a';
            const elements = document.querySelectorAll(selectors);
            const colors = [];
            const fonts = new Set();
            for (const el of elements) {
                const style = getComputedStyle(el);
                colors.push(style.color);
                colors.push(style.backgroundColor);
                const ff = style.fontFamily;
                if (ff) fonts.add(ff.split(',')[0].trim().replace(/['"]/g, ''));
            }
            return { colors, fonts: Array.from(fonts) };
        }""")
        result['colors'] = css_data.get('colors', [])
        result['fonts'] = css_data.get('fonts', [])
    except Exception as e:
        print(f"[BrandFingerprint] CSS extraction failed for {url}: {e}")

    try:
        # Find logo elements and compute perceptual hashes
        logo_elements = await page.evaluate("""() => {
            const logoSelectors = [
                'img[src*="logo"]', 'img[alt*="logo"]', 'img[class*="logo"]',
                'link[rel="icon"]', 'link[rel="shortcut icon"]',
                'img[src*="brand"]', 'img[alt*="brand"]',
            ];
            const results = [];
            const seen = new Set();
            for (const sel of logoSelectors) {
                for (const el of document.querySelectorAll(sel)) {
                    const src = el.src || el.href || '';
                    if (src && !seen.has(src)) {
                        seen.add(src);
                        const isIcon = el.tagName === 'LINK';
                        results.push({ src, type: isIcon ? 'favicon' : 'logo_img' });
                    }
                }
            }
            return results;
        }""")

        for logo_info in (logo_elements or []):
            logo_hash = await _download_and_hash(page, logo_info['src'])
            if logo_hash:
                entry = {
                    'hash': logo_hash,
                    'source': logo_info['type'],
                    'url': logo_info['src'],
                }
                result['logos'].append(entry)
                if logo_info['type'] == 'favicon' and not result['favicon']:
                    result['favicon'] = logo_hash
    except Exception as e:
        print(f"[BrandFingerprint] Logo extraction failed for {url}: {e}")

    try:
        # Extract layout structure
        layout = await page.evaluate("""() => {
            const structuralEls = {header: 'header', nav: 'nav', main: 'main', footer: 'footer'};
            const layout = {};
            for (const [key, tag] of Object.entries(structuralEls)) {
                const el = document.querySelector(tag);
                if (el) {
                    const rect = el.getBoundingClientRect();
                    layout[key] = {
                        top: Math.round(rect.top),
                        left: Math.round(rect.left),
                        width: Math.round(rect.width),
                        height: Math.round(rect.height),
                    };
                }
            }
            return layout;
        }""")
        result['layout'] = layout or {}
    except Exception as e:
        print(f"[BrandFingerprint] Layout extraction failed for {url}: {e}")

    try:
        # Extract text content
        texts = await page.evaluate("""() => {
            const texts = [];
            for (const tag of ['h1', 'h2', 'h3']) {
                for (const el of document.querySelectorAll(tag)) {
                    const t = el.textContent.trim();
                    if (t && t.length > 2 && t.length < 500) texts.push(t);
                }
            }
            const meta = document.querySelector('meta[name="description"]');
            if (meta && meta.content) texts.push(meta.content.trim());
            const footer = document.querySelector('footer');
            if (footer) {
                const ft = footer.textContent.trim().substring(0, 500);
                if (ft) texts.push(ft);
            }
            return texts;
        }""")
        result['texts'] = texts or []
    except Exception as e:
        print(f"[BrandFingerprint] Text extraction failed for {url}: {e}")

    return result


async def _download_and_hash(page, src: str) -> Optional[str]:
    """Download an image from src URL and compute its perceptual hash."""
    try:
        import imagehash
        from PIL import Image

        resp = await page.context.request.get(src, timeout=10000)
        if resp.status != 200:
            return None
        body = await resp.body()
        img = Image.open(io.BytesIO(body))
        phash = imagehash.phash(img)
        return str(phash)
    except Exception as e:
        print(f"[BrandFingerprint] Hash failed for {src}: {e}")
        return None


def _hash_local_image(file_path: str) -> Optional[str]:
    try:
        import imagehash
        from PIL import Image

        if not file_path or not os.path.exists(file_path):
            return None

        img = Image.open(file_path)
        return str(imagehash.phash(img))
    except Exception as e:
        print(f"[BrandFingerprint] Local hash failed for {file_path}: {e}")
        return None


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


def aggregate_identities(identities: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate identity data extracted from multiple URLs into a single fingerprint."""
    all_colors: List[str] = []
    all_logos: List[Dict[str, Any]] = []
    font_sets: List[set] = []
    all_texts: List[str] = []
    layout_flags = {'hasHeader': False, 'hasNav': False, 'hasMain': False, 'hasFooter': False}
    favicon_hash = None

    for identity in identities:
        # Colors
        for c in identity.get('colors', []):
            hex_c = _parse_color_hex(c)
            if hex_c and hex_c != '#000000' and hex_c != '#ffffff':
                all_colors.append(hex_c)

        # Logos
        seen_hashes = {l['hash'] for l in all_logos}
        for logo in identity.get('logos', []):
            if logo['hash'] not in seen_hashes:
                all_logos.append(logo)
                seen_hashes.add(logo['hash'])

        # Fonts
        fonts = identity.get('fonts', [])
        if fonts:
            font_sets.append(set(fonts))

        # Texts
        all_texts.extend(identity.get('texts', []))

        # Layout
        layout = identity.get('layout', {})
        for key in ['header', 'nav', 'main', 'footer']:
            camel = f'has{key.capitalize()}'
            if key in layout:
                layout_flags[camel] = True

        # Favicon
        if identity.get('favicon') and not favicon_hash:
            favicon_hash = identity['favicon']

    # Dominant colors by frequency
    color_counter = Counter(all_colors)
    total_colors = sum(color_counter.values()) or 1
    dominant_colors = [
        {'hex': hex_c, 'frequency': round(count / total_colors, 4)}
        for hex_c, count in color_counter.most_common(20)
    ]

    # Intersect fonts across pages (common fonts)
    if font_sets:
        common_fonts = font_sets[0]
        for fs in font_sets[1:]:
            common_fonts = common_fonts & fs
        if not common_fonts and font_sets:
            # Fallback: union if intersection is empty
            common_fonts = set()
            for fs in font_sets:
                common_fonts |= fs
        font_families = sorted(common_fonts)
    else:
        font_families = []

    # Common text patterns (appearing in more than one page)
    text_counter = Counter(all_texts)
    if len(identities) > 1:
        text_patterns = [t for t, c in text_counter.items() if c > 1]
    else:
        text_patterns = list(text_counter.keys())

    return {
        'dominantColors': dominant_colors,
        'logoHashes': all_logos,
        'fontFamilies': font_families,
        'layoutPatterns': layout_flags,
        'textPatterns': text_patterns[:50],
        'faviconHash': favicon_hash,
    }


class BrandFingerprintIdentityTool(ToolPlugin):
    @property
    def name(self) -> str:
        return "brand:fingerprint_identity"

    @property
    def description(self) -> str:
        return (
            "Extracts brand visual identity (colors, logos, fonts, layout, text) "
            "from reference URLs to build a brand fingerprint for typosquat scoring."
        )

    @property
    def schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "referenceUrls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "1-10 reference URLs for the brand"
                },
                "brandMonitorId": {
                    "type": "string",
                    "description": "Brand monitor ID to associate the fingerprint with"
                },
                "referenceAssets": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Optional uploaded brand reference assets (logo, favicon, screenshot)"
                },
            },
            "required": []
        }

    @property
    def metadata(self) -> Dict[str, Any]:
        return {
            "category": "brand",
            "phase": 3,
            "domain": ["web", "osint"],
            "input_type": ["url"],
            "output_type": ["fingerprint"],
            "chainable_after": ["typosquat:detect"],
            "chainable_before": ["brand:score_against_fingerprint"],
        }

    async def execute(self, parameters: Dict[str, Any]) -> Any:
        agent = parameters.get('_agent')

        reference_urls = parameters.get('referenceUrls', [])
        if isinstance(reference_urls, str):
            try:
                reference_urls = json.loads(reference_urls)
            except json.JSONDecodeError:
                reference_urls = [reference_urls]

        brand_monitor_id = parameters.get('brandMonitorId')
        reference_assets = parameters.get('referenceAssets', [])
        if isinstance(reference_assets, str):
            try:
                reference_assets = json.loads(reference_assets)
            except json.JSONDecodeError:
                reference_assets = []

        if not reference_urls and not reference_assets:
            return {
                'success': False,
                'error': 'Provide at least one reference URL or uploaded reference asset',
                'output': {
                    'fingerprint': None,
                    'referenceUrlsProcessed': 0,
                    'brandMonitorId': brand_monitor_id,
                    'tool': 'brand',
                    'scan_type': 'fingerprint_identity',
                }
            }

        if not brand_monitor_id:
            return {
                'success': False,
                'error': 'brandMonitorId parameter is required',
                'output': {
                    'fingerprint': None,
                    'referenceUrlsProcessed': 0,
                    'brandMonitorId': None,
                    'tool': 'brand',
                    'scan_type': 'fingerprint_identity',
                }
            }

        # Limit to 10 URLs
        reference_urls = reference_urls[:10]

        if agent:
            agent.report_progress(
                current_operation=f"Extracting brand identity from {len(reference_urls)} URL(s)",
                current_target=reference_urls[0],
                items_processed=0,
                total_items=len(reference_urls),
            )

        identities: List[Dict[str, Any]] = []
        errors: List[str] = []

        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=['--no-sandbox'])
                context = await browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                )

                for idx, url in enumerate(reference_urls):
                    try:
                        page = await context.new_page()
                        identity = await extract_page_identity(page, url)
                        await page.close()

                        if identity.get('error'):
                            errors.append(f"{url}: {identity['error']}")
                            print(f"[BrandFingerprint] Error for {url}: {identity['error']}")
                        else:
                            identities.append(identity)

                        if agent:
                            agent.report_progress(
                                current_operation="Extracting brand identity",
                                current_target=url,
                                items_processed=idx + 1,
                                total_items=len(reference_urls),
                            )
                            agent.append_output(
                                f"[BrandFingerprint] Processed {url}: "
                                f"{len(identity.get('colors', []))} colors, "
                                f"{len(identity.get('logos', []))} logos, "
                                f"{len(identity.get('fonts', []))} fonts"
                            )
                    except Exception as e:
                        errors.append(f"{url}: {str(e)[:200]}")
                        print(f"[BrandFingerprint] Failed for {url}: {e}")

                await browser.close()
        except Exception as e:
            return {
                'success': False,
                'error': f'Playwright browser launch failed: {str(e)[:300]}',
                'output': {
                    'fingerprint': None,
                    'referenceUrlsProcessed': 0,
                    'brandMonitorId': brand_monitor_id,
                    'tool': 'brand',
                    'scan_type': 'fingerprint_identity',
                }
            }

        if not identities and not reference_assets:
            return {
                'success': False,
                'error': f'All URLs failed: {"; ".join(errors[:5])}',
                'output': {
                    'fingerprint': None,
                    'referenceUrlsProcessed': 0,
                    'brandMonitorId': brand_monitor_id,
                    'tool': 'brand',
                    'scan_type': 'fingerprint_identity',
                }
            }

        fingerprint = aggregate_identities(identities) if identities else {
            'dominantColors': [],
            'logoHashes': [],
            'fontFamilies': [],
            'layoutPatterns': {},
            'textPatterns': [],
            'faviconHash': None,
        }

        normalized_assets: List[Dict[str, Any]] = []
        reference_image_hashes: List[Dict[str, Any]] = []
        seen_logo_hashes = {logo.get('hash') for logo in fingerprint.get('logoHashes', [])}

        for asset in reference_assets or []:
            if not isinstance(asset, dict):
                continue

            asset_type = str(asset.get('type', 'LOGO')).upper()
            asset_hash = _hash_local_image(asset.get('filePath', ''))
            normalized_asset = dict(asset)
            if asset_hash:
                normalized_asset['hash'] = asset_hash
            normalized_assets.append(normalized_asset)

            if not asset_hash:
                continue

            if asset_type == 'FAVICON':
                fingerprint['faviconHash'] = asset_hash
                if asset_hash not in seen_logo_hashes:
                    fingerprint['logoHashes'].append({
                        'hash': asset_hash,
                        'source': 'manual_favicon',
                        'fileName': asset.get('fileName'),
                    })
                    seen_logo_hashes.add(asset_hash)
            elif asset_type == 'LOGO':
                if asset_hash not in seen_logo_hashes:
                    fingerprint['logoHashes'].append({
                        'hash': asset_hash,
                        'source': 'manual_logo',
                        'fileName': asset.get('fileName'),
                    })
                    seen_logo_hashes.add(asset_hash)
            elif asset_type == 'SCREENSHOT':
                reference_image_hashes.append({
                    'hash': asset_hash,
                    'source': 'manual_screenshot',
                    'fileName': asset.get('fileName'),
                })

        fingerprint['referenceImageHashes'] = reference_image_hashes
        fingerprint['fingerprintVector'] = {
            'referenceAssets': normalized_assets,
            'referenceImageHashes': reference_image_hashes,
        }

        if agent:
            agent.report_progress(
                current_operation="Brand fingerprint extraction completed",
                current_target=reference_urls[0],
                items_processed=len(reference_urls),
                total_items=len(reference_urls),
            )
            agent.append_output(
                f"[BrandFingerprint] Fingerprint built from {len(identities)} URL(s) "
                f"and {len(normalized_assets)} uploaded asset(s): "
                f"{len(fingerprint['dominantColors'])} colors, "
                f"{len(fingerprint['logoHashes'])} logos, "
                f"{len(fingerprint['fontFamilies'])} fonts"
            )

        return {
            'success': True,
            'output': {
                'fingerprint': fingerprint,
                **fingerprint,
                'referenceUrlsProcessed': len(identities),
                'brandMonitorId': brand_monitor_id,
                'errors': errors if errors else None,
                'tool': 'brand',
                'scan_type': 'fingerprint_identity',
            }
        }


def get_tool():
    return BrandFingerprintIdentityTool()

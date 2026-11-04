# WP-DETECT — SPDX-License-Identifier: AGPL-3.0-or-later
"""Plugin / theme enumeration — parallel, dedupe, version sanity."""
import re
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from bs4 import XMLParsedAsHTMLWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
except ImportError:
    pass

# Reuse the same alias map — one source of truth
from .vuln import resolve_slug, _parse_version

CORE_NAMESPACES = {
    "wp", "oembed", "batch", "wp-site-health", "wp-block-editor",
    "wp-abilities", "wpcom", "my-jetpack", "wp-block-library",
    "wp-global-styles", "ai", "mcp", "abilities",
}

WPORG_PLUGIN_API = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"
WPORG_THEME_API = ("https://api.wordpress.org/themes/info/1.1/"
                   "?action=theme_information&request[slug]={slug}")

GENERATOR_MAP = [
    ("Elementor", "elementor"),
    ("WooCommerce", "woocommerce"),
    ("Site Kit", "google-site-kit"),
    ("Rank Math", "seo-by-rank-math"),
    ("All in One SEO", "all-in-one-seo-pack"),
    ("Jetpack", "jetpack"),
    ("Yoast", "wordpress-seo"),
]


# ────────────────────────────────────────────────────────────────────
# Dedupe + version sanity
# ────────────────────────────────────────────────────────────────────
def dedupe_plugins(plugins):
    """Merge detected slugs that resolve to the same WordPress.org slug."""
    if not plugins:
        return plugins

    groups = {}
    for p in plugins:
        key = resolve_slug(p["slug"]) or p["slug"]
        groups.setdefault(key, []).append(p)

    merged = []
    for resolved, group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
            continue
        primary = dict(group[0])
        all_sources = set()
        original_slugs = []
        best_version = None
        for p in group:
            all_sources |= set(p.get("sources", []))
            original_slugs.append(p["slug"])
            v = p.get("version")
            if v and not best_version:
                best_version = v
        primary["sources"] = sorted(all_sources)
        primary["original_slugs"] = original_slugs
        if best_version:
            primary["version"] = best_version
        merged.append(primary)
    return merged


def check_version_sanity_batch(plugins):
    """Mark detected versions as internal asset versions if they exceed
    WP.org's latest by a major version (catches Elementor 5.48.0 vs 4.3.6)."""
    for p in plugins:
        detected = p.get("version")
        if not detected or detected in ("?", "not detectable"):
            continue
        latest = (p.get("meta") or {}).get("latest_version")
        if not latest:
            continue
        det = _parse_version(detected)
        lat = _parse_version(latest)
        if det[0] > lat[0]:
            p["internal_version"] = detected
            p["version"] = None
            p["version_note"] = f"internal asset {detected} (WP.org latest: {latest})"
    return plugins


# ────────────────────────────────────────────────────────────────────
# Enumerator
# ────────────────────────────────────────────────────────────────────
class Enumerator:
    def __init__(self, base_url, session, timeout=15, max_workers=10):
        self.base = base_url.rstrip("/")
        self.session = session
        self.timeout = timeout
        self.max_workers = max_workers
        self._wporg_cache = {}

    def _get(self, path, **kw):
        url = path if path.startswith("http") else self.base + path
        try:
            return self.session.get(url, timeout=self.timeout,
                                    allow_redirects=True, **kw)
        except Exception:
            return None

    def passive(self, pages=("/", "/wp-login.php", "/feed/", "/sample-page/",
                             "/contact/", "/contact-us/", "/blog/", "/about/"),
                max_workers=None):
        max_workers = max_workers or min(len(pages), 8)
        found = {}
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(self._get, page): page for page in pages}
            for fut in as_completed(futures):
                page = futures[fut]
                r = fut.result()
                if r is None:
                    continue
                self._parse_refs(r.text or "", page, found)
        for f in found.values():
            f["sources"] = sorted(f["sources"])
        return list(found.values())

    def _parse_refs(self, body, page, found):
        for m in re.finditer(r"/wp-content/plugins/([a-z0-9_\-]+)/", body, re.I):
            slug = m.group(1).lower()
            found.setdefault(slug, {"slug": slug, "sources": set(), "version": None})
            found[slug]["sources"].add(page)
        for m in re.finditer(
            r"/wp-content/plugins/([a-z0-9_\-]+)/[^\"']+\?ver=([\d\.]+)",
            body, re.I):
            slug, ver = m.group(1).lower(), m.group(2)
            found.setdefault(slug, {"slug": slug, "sources": set(), "version": None})
            found[slug]["sources"].add(page)
            if not found[slug]["version"]:
                found[slug]["version"] = ver
        try:
            soup = BeautifulSoup(body, "html.parser")
            for meta in soup.find_all("meta", attrs={"name": "generator"}):
                content = (meta.get("content") or "").lower()
                for known, slug in GENERATOR_MAP:
                    if known.lower() in content:
                        found.setdefault(slug, {"slug": slug,
                                                "sources": set(), "version": None})
                        found[slug]["sources"].add(page)
        except Exception:
            pass

    def rest_api(self):
        slugs = set()
        for path in ("/wp-json/", "/?rest_route=/"):
            r = self._get(path)
            if r is None or r.status_code != 200:
                continue
            try:
                data = r.json()
            except Exception:
                continue
            namespaces = data.get("namespaces", []) if isinstance(data, dict) else []
            routes = data.get("routes", {}) if isinstance(data, dict) else {}
            for ns in namespaces:
                slug = ns.split("/")[0].lower()
                if slug and slug not in CORE_NAMESPACES:
                    slugs.add(slug)
            if isinstance(routes, dict):
                for route in routes.keys():
                    m = re.match(r"/([a-z0-9_\-]+)/v\d", route, re.I)
                    if m and m.group(1).lower() not in CORE_NAMESPACES:
                        slugs.add(m.group(1).lower())
            break
        return [{"slug": s, "version": None, "sources": ["rest_api"]}
                for s in sorted(slugs)]

    def aggressive(self, slugs, delay=0.0):
        def probe(slug):
            r = self._get(f"/wp-content/plugins/{slug}/readme.txt")
            if r is not None and r.status_code == 200:
                m = re.search(r"Stable tag:\s*([\d\.]+)", r.text or "")
                return {"slug": slug,
                        "version": m.group(1) if m else None,
                        "sources": ["aggressive_probe"]}
            return None
        out = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for res in ex.map(probe, slugs):
                if res:
                    out.append(res)
        return out

    def themes_passive(self, pages=("/", "/wp-login.php"), max_workers=2):
        found = {}
        def fetch(page):
            return page, self._get(page)
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            for page, r in ex.map(fetch, pages):
                if r is None:
                    continue
                body = r.text or ""
                for m in re.finditer(r"/wp-content/themes/([a-z0-9_\-]+)/", body, re.I):
                    slug = m.group(1).lower()
                    found.setdefault(slug, {"slug": slug, "version": None,
                                            "sources": []})
                    if page not in found[slug]["sources"]:
                        found[slug]["sources"].append(page)
                for m in re.finditer(
                    r"/wp-content/themes/([a-z0-9_\-]+)/[^\"']+\?ver=([\d\.]+)",
                    body, re.I):
                    slug, ver = m.group(1).lower(), m.group(2)
                    found.setdefault(slug, {"slug": slug, "version": None,
                                            "sources": []})
                    if not found[slug]["version"]:
                        found[slug]["version"] = ver
        return list(found.values())

    def hybrid(self, aggressive_slugs=None, delay=0.0,
               probe_readme=False, max_workers=None):
        max_workers = max_workers or self.max_workers
        with ThreadPoolExecutor(max_workers=2) as ex:
            fp = ex.submit(self.passive, max_workers=4)
            fr = ex.submit(self.rest_api)
            passive, rest = fp.result(), fr.result()

        by_slug = {p["slug"]: p for p in passive}
        for p in rest:
            if p["slug"] in by_slug:
                by_slug[p["slug"]]["sources"] = sorted(
                    set(by_slug[p["slug"]]["sources"]) | set(p["sources"]))
            else:
                by_slug[p["slug"]] = p

        if aggressive_slugs:
            for p in self.aggressive(aggressive_slugs):
                if p["slug"] in by_slug:
                    by_slug[p["slug"]]["version"] = (
                        by_slug[p["slug"]]["version"] or p["version"])
                    by_slug[p["slug"]]["sources"] = sorted(
                        set(by_slug[p["slug"]]["sources"]) | set(p["sources"]))
                else:
                    by_slug[p["slug"]] = p

        if probe_readme:
            missing = [s for s, p in by_slug.items() if not p.get("version")]
            def probe(slug):
                r = self._get(f"/wp-content/plugins/{slug}/readme.txt")
                if r is not None and r.status_code == 200:
                    m = re.search(r"Stable tag:\s*([\d\.]+)", r.text or "")
                    if m:
                        return slug, m.group(1)
                return slug, None
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                for slug, ver in ex.map(probe, missing):
                    if ver:
                        by_slug[slug]["version"] = ver
                        by_slug[slug]["sources"] = sorted(
                            set(by_slug[slug]["sources"]) | {"readme.txt"})
        return list(by_slug.values())

    def enrich_plugins_parallel(self, plugins, max_workers=None):
        max_workers = max_workers or self.max_workers
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(self.enrich_plugin, p["slug"]): p
                       for p in plugins}
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    p["meta"] = fut.result()
                except Exception:
                    p["meta"] = {"name": None, "author": None,
                                 "latest_version": None}
        return plugins

    def enrich_themes_parallel(self, themes, max_workers=None):
        max_workers = max_workers or self.max_workers
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(self.enrich_theme, t["slug"]): t
                       for t in themes}
            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    t["meta"] = fut.result()
                except Exception:
                    t["meta"] = {"name": None, "author": None,
                                 "parent": None, "latest_version": None}
        return themes

    def enrich_plugin(self, slug):
        real = resolve_slug(slug)
        if real is None:
            return {"name": None, "author": None, "latest_version": None}
        if real in self._wporg_cache:
            return self._wporg_cache[real]
        out = {"name": None, "author": None, "latest_version": None,
               "last_updated": None, "active_installs": None}
        try:
            r = self.session.get(WPORG_PLUGIN_API.format(slug=real),
                                 timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict) and not data.get("error"):
                    out["name"] = data.get("name")
                    out["author"] = re.sub(r"<[^>]+>", "",
                                           data.get("author", "") or "")
                    out["latest_version"] = data.get("version")
                    out["last_updated"] = (data.get("last_updated") or "")[:10] or None
                    out["active_installs"] = data.get("active_installs")
        except Exception:
            pass
        self._wporg_cache[real] = out
        return out

    def enrich_theme(self, slug):
        key = f"theme:{slug}"
        if key in self._wporg_cache:
            return self._wporg_cache[key]
        out = {"name": None, "author": None, "parent": None,
               "latest_version": None}
        try:
            r = self.session.get(WPORG_THEME_API.format(slug=slug),
                                 timeout=self.timeout)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, dict):
                    out["name"] = data.get("name")
                    out["author"] = re.sub(r"<[^>]+>", "",
                                           data.get("author", "") or "")
                    out["parent"] = data.get("template")
                    out["latest_version"] = data.get("version")
        except Exception:
            pass
        self._wporg_cache[key] = out
        return out

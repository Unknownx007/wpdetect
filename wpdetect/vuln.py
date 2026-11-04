# WP-DETECT — SPDX-License-Identifier: AGPL-3.0-or-later
"""Vulnerability matching — WPVulnerability.net (free, accurate)."""
import html as _html
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

WPVULN_HOST = "https://www.wpvulnerability.net"
CACHE_DIR = Path.home() / ".wpdetect" / "cache"
CACHE_TTL = 7200

# ────────────────────────────────────────────────────────────────────
# Slug aliases — ONLY real directory→slug renames. Premium sub-plugins
# map to None (skip lookup entirely, show 0 CVEs for them).
# ────────────────────────────────────────────────────────────────────
SLUG_ALIASES = {
    # Legit renames — same plugin, different directory name
    "rankmath": "seo-by-rank-math",
    "seo-by-rank-math": "seo-by-rank-math",
    "litespeed": "litespeed-cache",
    "litespeed-cache": "litespeed-cache",
    "joinchat": "creame-whatsapp-me",
    "creame-whatsapp-me": "creame-whatsapp-me",
    # Premium / nulled — NOT on WP.org, treat as their own plugin with 0 CVEs
    "elementor-ai": None,
    "elementor-one": None,
    "elementor-pro": None,
    "pro-elements": None,
    "wp-rocket": None,
    "gravityforms": None,
    "advanced-custom-fields-pro": None,
    "woocommerce-subscriptions": None,
    "yoast-seo-premium": None,
}


def resolve_slug(detected_slug):
    """Map a detected directory slug to its WP.org slug, or None if premium."""
    if not detected_slug:
        return None
    s = detected_slug.lower().strip()
    if s in SLUG_ALIASES:
        return SLUG_ALIASES[s]
    return s


# ────────────────────────────────────────────────────────────────────
# Version helpers
# ────────────────────────────────────────────────────────────────────
def _parse_version(v):
    if not v:
        return (0, 0, 0)
    parts = re.findall(r"\d+", str(v))
    while len(parts) < 3:
        parts.append("0")
    return tuple(int(p) for p in parts[:3])


def _cmp(a, op, b):
    op = (op or "").lower().strip()
    if op in ("lt", "<"):     return a < b
    if op in ("lte", "<=", "le"): return a <= b
    if op in ("gt", ">"):     return a > b
    if op in ("gte", ">=", "ge"): return a >= b
    if op in ("eq", "=", "=="): return a == b
    if op in ("ne", "!=", "<>"): return a != b
    return True


def vuln_affects_version(vuln, installed_version):
    if not installed_version:
        return True
    inst = _parse_version(installed_version)
    max_v = vuln.get("max_version")
    max_op = vuln.get("max_operator")
    if max_v and not _cmp(inst, max_op or "lt", _parse_version(max_v)):
        return False
    min_v = vuln.get("min_version")
    min_op = vuln.get("min_operator")
    if min_v and not _cmp(inst, min_op or "gte", _parse_version(min_v)):
        return False
    return True


# ────────────────────────────────────────────────────────────────────
# Title extraction — get the descriptive name from sources, not the
# plugin name that the API puts in the record's `name` field.
# ────────────────────────────────────────────────────────────────────
def _extract_title(v, sources):
    """Best title: Patchstack/WPScan/Wordfence descriptive name first,
    then CVE description, then fall back to the record name."""
    # First pass: descriptive source names
    for src in sources:
        if not isinstance(src, dict):
            continue
        src_name = src.get("name", "")
        src_id = src.get("id", "")
        if not src_name or src_name == src_id or src_name.startswith("CVE-"):
            continue
        title = _html.unescape(str(src_name))
        if title.lower().startswith("wordpress "):
            title = title[10:]
        return title[:90]
    # Second pass: CVE description
    for src in sources:
        if isinstance(src, dict):
            desc = src.get("description") or ""
            if desc.startswith("[en] "):
                desc = desc[5:]
            if desc:
                return _html.unescape(desc[:90])
    # Fallback
    return _html.unescape(v.get("name", "Unknown"))[:90]


# ────────────────────────────────────────────────────────────────────
# Matcher
# ────────────────────────────────────────────────────────────────────
class VulnMatcher:
    def __init__(self, timeout=25, cache=True, max_workers=8, debug=False):
        self.timeout = timeout
        self.use_cache = cache
        self.max_workers = max_workers
        self.debug = debug
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "WP-DETECT/1.0"
        self.session.verify = False
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._debug_log = []

    def _cache_path(self, key):
        return CACHE_DIR / key

    def _read_cache(self, key):
        if not self.use_cache:
            return None
        p = self._cache_path(key)
        if not p.exists():
            return None
        if time.time() - p.stat().st_mtime > CACHE_TTL:
            return None
        try:
            return json.loads(p.read_text())
        except Exception:
            return None

    def _write_cache(self, key, data):
        if not self.use_cache:
            return
        try:
            self._cache_path(key).write_text(json.dumps(data))
        except Exception:
            pass

    def _debug(self, label, data):
        if self.debug:
            self._debug_log.append({
                "label": label,
                "snippet": json.dumps(data, default=str)[:1000],
            })

    def get_debug_log(self):
        return self._debug_log

    # ── normalizer ─────────────────────────────────────────────
    def _normalize_vuln(self, v):
        if not isinstance(v, dict):
            return None

        sources = v.get("source", []) or []
        title = _extract_title(v, sources)

        # CVE + published date from sources
        cve = "N/A"
        published = None
        ref_link = None
        for src in sources:
            if not isinstance(src, dict):
                continue
            sid = str(src.get("id", ""))
            if sid.startswith("CVE-") and cve == "N/A":
                cve = sid
                ref_link = src.get("link")
            if not published and src.get("date"):
                published = str(src["date"])[:10]
        if cve == "N/A" and sources:
            first = sources[0]
            if isinstance(first, dict):
                cve = first.get("id", "N/A")
                ref_link = first.get("link")

        # Operator — OBJECT {max_version, max_operator, min_version, min_operator}
        operator = v.get("operator", {})
        max_version = max_operator = min_version = min_operator = None
        if isinstance(operator, dict):
            max_version = operator.get("max_version")
            max_operator = operator.get("max_operator") or "lt"
            min_version = operator.get("min_version")
            min_operator = operator.get("min_operator") or "gte"
        elif isinstance(operator, str):
            max_operator = operator

        if min_version and max_version:
            affected = f">= {min_version} and < {max_version}"
        elif max_version:
            affected = f"< {max_version}"
        elif min_version:
            affected = f">= {min_version}"
        else:
            affected = "unknown range"

        # CVSS from impact.cvss3 / impact.cvss
        cvss = None
        severity = None
        impact = v.get("impact", {})
        if isinstance(impact, dict):
            for key in ("cvss3", "cvss"):
                block = impact.get(key)
                if isinstance(block, dict):
                    score = block.get("score")
                    if score:
                        try:
                            cvss = float(score)
                        except (ValueError, TypeError):
                            cvss = None
                        severity = (block.get("severity") or "").upper() or None
                        break

        return {
            "cve": cve,
            "title": title,
            "affected": affected,
            "max_version": max_version,
            "max_operator": max_operator,
            "min_version": min_version,
            "min_operator": min_operator,
            "cvss": cvss,
            "severity": severity,
            "source": "wpvulnerability.net",
            "fixed_in": max_version,
            "published": published,
            "reference": ref_link,
        }

    def _parse_response(self, data):
        if not isinstance(data, dict):
            return []
        inner = data.get("data")
        if not isinstance(inner, dict):
            return []
        items = inner.get("vulnerability")
        if not isinstance(items, list):
            return []
        return items

    # ── plugin lookup ──────────────────────────────────────────
    def lookup_plugin(self, detected_slug):
        real_slug = resolve_slug(detected_slug)
        if real_slug is None:
            return []  # premium — no WP.org entry

        cache_key = f"wpvuln_plugin_{real_slug}.json"
        cached = self._read_cache(cache_key)
        if cached is not None:
            raw = cached
        else:
            try:
                r = self.session.get(f"{WPVULN_HOST}/plugin/{real_slug}/",
                                     timeout=self.timeout)
            except Exception:
                return []
            if r.status_code != 200:
                return []
            try:
                data = r.json()
            except Exception:
                return []
            raw = self._parse_response(data)
            self._write_cache(cache_key, raw)

        return [n for n in (self._normalize_vuln(v) for v in raw) if n]

    # ── core lookup ────────────────────────────────────────────
    def lookup_core(self, version):
        if not version:
            return []
        cache_key = f"wpvuln_core_{version}.json"
        cached = self._read_cache(cache_key)
        if cached is not None:
            raw = cached
        else:
            try:
                r = self.session.get(f"{WPVULN_HOST}/core/{version}/",
                                     timeout=self.timeout)
            except Exception:
                return []
            if r.status_code != 200:
                return []
            try:
                data = r.json()
            except Exception:
                return []
            raw = self._parse_response(data)
            self._write_cache(cache_key, raw)

        out = []
        for v in raw:
            n = self._normalize_vuln(v)
            if n:
                n["affected"] = f"core {version}"
                out.append(n)
        return out

    # ── parallel enrichment ────────────────────────────────────
    def enrich(self, plugins):
        if not plugins:
            return plugins

        def _fetch(p):
            installed = p.get("version")
            if installed in (None, "", "not detectable"):
                vulns = self.lookup_plugin(p["slug"])
                return p, [], vulns
            all_v = self.lookup_plugin(p["slug"])
            affecting = [v for v in all_v
                         if vuln_affects_version(v, installed)]
            return p, affecting, all_v

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for fut in as_completed([ex.submit(_fetch, p) for p in plugins]):
                try:
                    p, affecting, all_v = fut.result()
                    p["vulnerabilities"] = affecting
                    p["historical_vulnerabilities"] = (
                        all_v if not affecting and all_v else []
                    )
                except Exception:
                    pass
        return plugins

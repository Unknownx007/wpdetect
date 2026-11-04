# WP-DETECT — SPDX-License-Identifier: AGPL-3.0-or-later
"""WordPress detection + tech stack fingerprinting."""
import re
import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from Wappalyzer import Wappalyzer, WebPage
    HAS_WAPPALYZER = True
except ImportError:
    HAS_WAPPALYZER = False


class Scanner:
    def __init__(self, base_url, timeout=15):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            "Mozilla/5.0 (WP-DETECT v1.0; authorized security assessment)"
        )
        self.session.verify = False
        self.evidence = []
        self.is_wordpress = False
        self.version = None
        self.version_sources = []

    def _get(self, path, **kw):
        url = path if path.startswith("http") else self.base + path
        try:
            return self.session.get(url, timeout=self.timeout,
                                    allow_redirects=True, **kw)
        except Exception:
            return None

    def run(self):
        self._homepage()
        self._wp_json()
        self._feed()
        self._readme()
        self._login_page()
        self._resolve_version()
        return {
            "is_wordpress": self.is_wordpress,
            "version": self.version,
            "version_sources": self.version_sources,
            "evidence": self.evidence,
        }

    def _homepage(self):
        r = self._get("/")
        if r is None:
            return
        body = r.text or ""
        if "wp-content/" in body or "wp-includes/" in body:
            self.is_wordpress = True
            self.evidence.append("wp-content/ or wp-includes/ present")
        soup = BeautifulSoup(body, "html.parser")
        gen = soup.find("meta", attrs={"name": "generator"})
        if gen and "wordpress" in gen.get("content", "").lower():
            self.is_wordpress = True
            self._try_version(gen["content"], "meta generator")
        if soup.find("link", rel="https://api.w.org/"):
            self.is_wordpress = True
            self.evidence.append("api.w.org link tag present")
        m = re.search(
            r"wp-includes/(?:css|js)/[^?\"']+\?ver=(\d+\.\d+(?:\.\d+)?)", body)
        if m:
            self._try_version(m.group(1), "asset ?ver=")

    def _wp_json(self):
        r = self._get("/wp-json/")
        if r is None or r.status_code != 200:
            return
        try:
            data = r.json()
        except Exception:
            return
        if isinstance(data, dict) and ("namespaces" in data or "routes" in data):
            self.is_wordpress = True
            self.evidence.append("wp-json REST API accessible")

    def _feed(self):
        r = self._get("/feed/")
        if r is None or r.status_code != 200:
            return
        m = re.search(r"<generator>[^<]*wordpress[^<]*?v=(\d+\.\d+(?:\.\d+)?)",
                      r.text or "", re.I)
        if m:
            self._try_version(m.group(1), "feed generator")

    def _readme(self):
        r = self._get("/readme.html")
        if r is None or r.status_code != 200:
            return
        m = re.search(r"Version\s+(\d+\.\d+(?:\.\d+)?)", r.text or "")
        if m:
            self.is_wordpress = True
            self._try_version(m.group(1), "readme.html")

    def _login_page(self):
        r = self._get("/wp-login.php")
        if r is not None and r.status_code == 200 and "user_login" in (r.text or ""):
            self.is_wordpress = True
            self.evidence.append("wp-login.php present")

    def _try_version(self, v, source):
        if not re.match(r"^\d+\.\d+(\.\d+)?", v):
            return
        self.version_sources.append({"version": v, "source": source})
        if self.version is None:
            self.version = v

    def _resolve_version(self):
        if not self.version_sources:
            return
        from collections import Counter
        self.version = Counter(s["version"] for s in self.version_sources).most_common(1)[0][0]

    # ──────────────────────────────────────────────────────────
    # TECH STACK — Wappalyzer (1,400+ fingerprints)
    # ──────────────────────────────────────────────────────────
    def tech_stack(self):
        if not HAS_WAPPALYZER:
            return {"error": "wappalyzer-python3 not installed"}
        try:
            wapp = Wappalyzer.latest()
            webpage = WebPage.new_from_url(self.base, timeout=self.timeout)
            results = wapp.analyze_with_versions_and_categories(webpage)
            return results
        except Exception as e:
            return {"error": str(e)}

    # ──────────────────────────────────────────────────────────
    # FEATURES
    # ──────────────────────────────────────────────────────────
    def check_features(self):
        xmlrpc_on = False
        r = self._get("/xmlrpc.php")
        if r is not None and r.status_code == 200:
            payload = ('<?xml version="1.0"?><methodCall>'
                       '<methodName>system.listMethods</methodName>'
                       '<params></params></methodCall>')
            try:
                rr = self.session.post(self.base + "/xmlrpc.php", data=payload,
                                       headers={"Content-Type": "text/xml"},
                                       timeout=self.timeout)
                xmlrpc_on = rr.status_code == 200 and "wp.getUsersBlogs" in (rr.text or "")
            except Exception:
                pass
        rest_on = False
        namespaces = []
        r = self._get("/wp-json/")
        if r is not None and r.status_code == 200:
            rest_on = True
            try:
                data = r.json()
                namespaces = data.get("namespaces", []) if isinstance(data, dict) else []
            except Exception:
                pass
        return {
            "xmlrpc": {"enabled": xmlrpc_on},
            "rest_api": {"enabled": rest_on, "namespaces": namespaces},
        }

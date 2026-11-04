# WP-DETECT — SPDX-License-Identifier: AGPL-3.0-or-later
"""Domain intelligence — RDAP with 3 fallback mirrors."""
import subprocess
import re
from datetime import datetime

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def _parse_rdap(data, domain):
    out = {
        "available": True, "registrar": None, "created": None,
        "expires": None, "age_days": None, "age_years": None,
        "nameservers": [],
    }
    for ent in data.get("entities", []) or []:
        if "registrar" in ent.get("roles", []):
            vcard = ent.get("vcardArray", [None, []])
            if len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn" and item[3]:
                        out["registrar"] = item[3]
                        break
    for ev in data.get("events", []) or []:
        action = (ev.get("eventAction") or "").lower()
        date = ev.get("eventDate", "")
        if action == "registration":
            out["created"] = date[:10]
            try:
                created = datetime.fromisoformat(date.replace("Z", "+00:00"))
                age = (datetime.now(created.tzinfo) - created).days
                out["age_days"] = age
                out["age_years"] = round(age / 365.25, 1)
            except Exception:
                pass
        elif action == "expiration":
            out["expires"] = date[:10]
    out["nameservers"] = [ns.get("ldhName", "").lower()
                          for ns in data.get("nameservers", []) or []]
    return out


def _try_rdap(url, domain, timeout):
    try:
        r = requests.get(url, timeout=timeout, verify=False,
                         headers={"User-Agent": "WP-DETECT/1.0",
                                  "Accept": "application/rdap+json"})
        if r.status_code == 200:
            return _parse_rdap(r.json(), domain)
    except Exception:
        pass
    return None


def _whois_fallback(domain):
    """Last resort — parse whois command output."""
    try:
        r = subprocess.run(["whois", domain], capture_output=True,
                           text=True, timeout=15)
        out = {
            "available": True, "registrar": None, "created": None,
            "expires": None, "age_days": None, "age_years": None,
            "nameservers": [],
        }
        for line in r.stdout.splitlines():
            low = line.lower()
            if "registrar:" in low and not out["registrar"]:
                out["registrar"] = line.split(":", 1)[1].strip()
            elif "creation date:" in low and not out["created"]:
                out["created"] = line.split(":", 1)[1].strip()[:10]
            elif "expir" in low and "date:" in low and not out["expires"]:
                out["expires"] = line.split(":", 1)[1].strip()[:10]
            elif "name server:" in low:
                ns = line.split(":", 1)[1].strip().lower()
                if ns and ns not in out["nameservers"]:
                    out["nameservers"].append(ns)
        if out["created"]:
            try:
                created = datetime.strptime(out["created"][:10], "%Y-%m-%d")
                age = (datetime.now() - created).days
                out["age_days"] = age
                out["age_years"] = round(age / 365.25, 1)
            except Exception:
                pass
        return out if out["registrar"] or out["created"] else None
    except Exception:
        return None


def lookup(domain, timeout=15):
    """Try ipwho.is, then RDAP mirrors, then whois."""
    # 1. ipwho.is — free, no rate limit, always works
    try:
        import requests
        r = requests.get(f"https://ipwho.is/{domain}",
                        timeout=timeout, verify=False,
                        headers={"User-Agent": "WP-DETECT/1.0"})
        if r.status_code == 200:
            data = r.json()
            if data.get("success"):
                conn = data.get("connection") or {}
                out = {
                    "available": True,
                    "registrar": conn.get("isp") or conn.get("org") or None,
                    "created": None, "expires": None,
                    "age_days": None, "age_years": None,
                    "nameservers": [],
                }
                # ipwho.is doesn't return WHOIS dates — use it only
                # if RDAP fails, and mark it clearly
                if out["registrar"]:
                    # still try RDAP for dates
                    tld = domain.rsplit(".", 1)[-1].lower()
                    for url in (
                        f"https://rdap.verisign.com/{tld}/v1/domain/{domain}",
                        f"https://rdap.org/domain/{domain}",
                    ):
                        rdap = _try_rdap(url, domain, timeout)
                        if rdap and rdap.get("created"):
                            return rdap
                    # Return minimal info from ipwho.is
                    out["nameservers"] = conn.get("domain", "").split(", ") if conn.get("domain") else []
                    return out
    except Exception:
        pass

    # 2. RDAP mirrors
    tld = domain.rsplit(".", 1)[-1].lower()
    for url in (
        f"https://rdap.verisign.com/{tld}/v1/domain/{domain}",
        f"https://rdap.org/domain/{domain}",
        f"https://rdap.iana.org/domain/{domain}",
    ):
        result = _try_rdap(url, domain, timeout)
        if result and result.get("created"):
            return result

    # 3. whois binary (only if installed)
    import shutil
    if shutil.which("whois"):
        whois_result = _whois_fallback(domain)
        if whois_result:
            return whois_result

    return {"available": False, "reason": "all sources failed"}

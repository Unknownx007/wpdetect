#!/usr/bin/env python3
# WP-DETECT — SPDX-License-Identifier: AGPL-3.0-or-later
"""Standalone diagnostic — shows the raw API response for a plugin."""
import json
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SLUGS = sys.argv[1:] or ["jetpack", "elementor", "seo-by-rank-math", "contact-form-7"]

for slug in SLUGS:
    print(f"\n{'=' * 70}")
    print(f"  WPVulnerability.net — plugin: {slug}")
    print(f"{'=' * 70}")
    url = f"https://www.wpvulnerability.net/plugin/{slug}/"
    print(f"  GET {url}")
    try:
        r = requests.get(url, timeout=20, verify=False,
                         headers={"User-Agent": "WP-DETECT/1.0"})
    except Exception as e:
        print(f"  ✗ request failed: {e}")
        continue

    print(f"  HTTP {r.status_code}  ({len(r.text)} bytes)")
    try:
        data = r.json()
    except Exception as e:
        print(f"  ✗ not JSON: {e}")
        print(f"  body[:500]: {r.text[:500]}")
        continue

    # Show top-level keys
    print(f"  top-level keys: {list(data.keys()) if isinstance(data, dict) else type(data).__name__}")
    print(f"\n  RAW JSON (first 3000 chars):")
    print(f"  {json.dumps(data, indent=2)[:3000]}")

    # Try our parser
    from wpdetect.vuln import VulnMatcher
    m = VulnMatcher()
    parsed = m._parse_wpvuln_response(data)
    print(f"\n  PARSED: {len(parsed)} vulnerability records")

    # Show first 2 normalized
    for v in parsed[:2]:
        n = m._normalize_vuln(v, "wpvulnerability.net")
        print(f"    {json.dumps(n, indent=6)}")

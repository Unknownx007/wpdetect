# WP-DETECT — SPDX-License-Identifier: AGPL-3.0-or-later
"""Mandatory scope enforcement — the tool refuses to scan out-of-scope domains."""
import os
from pathlib import Path
from urllib.parse import urlparse


class OutOfScopeError(Exception):
    pass


def load_scope(path):
    p = Path(os.path.expanduser(path))
    if not p.is_file():
        raise OutOfScopeError(f"scope file not found: {path}")
    hosts = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        hosts.append(line.lower())
    if not hosts:
        raise OutOfScopeError(f"scope file is empty: {path}")
    return hosts


def enforce(target_url, scope_hosts):
    if not target_url:
        raise OutOfScopeError("no target URL provided")
    if "://" not in target_url:
        target_url = "http://" + target_url
    host = urlparse(target_url).hostname
    if not host:
        raise OutOfScopeError(f"cannot parse hostname from: {target_url}")
    host = host.lower()
    for s in scope_hosts:
        if s == host:
            return host
        if s.startswith("*.") and host.endswith(s[1:]):
            return host
    raise OutOfScopeError(
        f"'{host}' is NOT in scope.txt. "
        f"Add it explicitly if you have written authorization to test it."
    )

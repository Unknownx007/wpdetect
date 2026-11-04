# WP-DETECT — SPDX-License-Identifier: AGPL-3.0-or-later
"""Rendering — DetectWP-equivalent output, no truncation."""
import html as _html
import json
from rich.table import Table
from rich.panel import Panel
from rich.console import Console

console = Console(highlight=False, force_terminal=True)


def _clean(s):
    if not s:
        return s
    try:
        return _html.unescape(str(s))
    except Exception:
        return str(s)


def render_detection(info):
    lines = [
        f"[bright_cyan]WordPress :[/] [bold green]yes[/]",
        f"[bright_cyan]Version   :[/] {info.get('version') or 'unknown'}",
        f"[bright_cyan]Confidence:[/] "
        f"{'high' if len(info.get('version_sources', [])) >= 2 else 'low'}",
    ]
    for e in info.get("evidence", [])[:5]:
        lines.append(f"[dim]  · {e}[/]")
    console.print(Panel("\n".join(lines),
                        title="[bold bright_cyan]◆  CMS Detection[/]",
                        title_align="left", border_style="bright_cyan",
                        padding=(0, 1)))


def render_tech_stack(tech):
    if not tech or tech.get("error"):
        console.print("[dim]  tech stack: unavailable[/]")
        return
    groups = {}
    for name, data in tech.items():
        cats = data.get("categories", ["Other"])
        versions = data.get("versions", [])
        ver = f" v{versions[0]}" if versions else ""
        for cat in cats:
            groups.setdefault(cat, []).append(f"{name}{ver}")
    tbl = Table(title="[bold bright_cyan]Tech Stack[/]",
                title_justify="left", border_style="bright_cyan")
    tbl.add_column("Category", style="bright_yellow bold")
    tbl.add_column("Technologies", style="white")
    for cat in sorted(groups):
        tbl.add_row(cat, ", ".join(sorted(groups[cat])))
    console.print(tbl)


def _version_cell(p):
    installed = p.get("version") or "?"
    latest = (p.get("meta") or {}).get("latest_version") or "?"
    note = p.get("version_note")
    if installed in (None, "?", "not detectable"):
        if note:
            return f"[dim]not detectable[/] [dim italic]({note})[/]"
        return "[dim]not detectable[/]"
    if latest and latest != "?" and installed != latest:
        return f"[bright_white]{installed}[/] [yellow]→[/] [green]{latest}[/]"
    return f"[bright_white]{installed}[/]"


def render_plugins(plugins):
    if not plugins:
        console.print("[dim]  no plugins detected[/]")
        return
    tbl = Table(title="[bold bright_cyan]Plugins[/]",
                title_justify="left", border_style="bright_cyan")
    tbl.add_column("Plugin", style="bright_white", max_width=44)
    tbl.add_column("Installed → Latest", style="cyan", max_width=42)
    tbl.add_column("CVEs", justify="center", style="bold", max_width=10)
    tbl.add_column("Author", style="dim", max_width=24)

    def sort_key(p):
        return (-len(p.get("vulnerabilities", [])),
                -len(p.get("historical_vulnerabilities", [])),
                (_clean((p.get("meta") or {}).get("name")) or p["slug"]).lower())

    for p in sorted(plugins, key=sort_key):
        meta = p.get("meta") or {}
        name = _clean(meta.get("name")) or p["slug"]
        author = _clean(meta.get("author")) or "?"
        n_aff = len(p.get("vulnerabilities", []))
        n_hist = len(p.get("historical_vulnerabilities", []))
        if n_aff:
            cve_cell = f"[bold red]{n_aff}[/]"
        elif n_hist:
            cve_cell = f"[yellow]{n_hist} hist.[/]"
        else:
            cve_cell = "[dim]0[/]"
        tbl.add_row(name, _version_cell(p), cve_cell, author)
    console.print(tbl)


def render_themes(themes):
    if not themes:
        return
    tbl = Table(title="[bold bright_cyan]Themes[/]",
                title_justify="left", border_style="bright_cyan")
    tbl.add_column("Theme", style="bright_white", max_width=36)
    tbl.add_column("Installed → Latest", style="cyan", max_width=32)
    tbl.add_column("Parent", style="dim", max_width=22)
    tbl.add_column("Author", style="dim", max_width=24)
    for t in themes:
        meta = t.get("meta") or {}
        name = _clean(meta.get("name")) or t["slug"]
        parent = _clean(meta.get("parent")) or "—"
        author = _clean(meta.get("author")) or "?"
        tbl.add_row(name, _version_cell(t), parent, author)
    console.print(tbl)


def render_vulns(plugins):
    rows = []
    for p in plugins:
        meta = p.get("meta") or {}
        pname = _clean(meta.get("name")) or p["slug"]
        installed = p.get("version") or "?"
        for v in p.get("vulnerabilities", []):
            cve = v.get("cve", "N/A")
            if cve == "N/A" and not v.get("title"):
                continue
            rows.append({
                "plugin": pname,
                "installed": installed,
                "cve": cve,
                "title": _clean(v.get("title") or ""),
                "severity": (v.get("severity") or "").upper(),
                "cvss": v.get("cvss"),
                "fixed_in": v.get("fixed_in") or "?",
                "published": v.get("published") or "",
            })

    if not rows:
        console.print("[green]  ✓  no known vulnerabilities affecting installed versions[/]")
        return

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "": 4, None: 4}
    rows.sort(key=lambda r: (order.get(r["severity"], 4), -(r["cvss"] or 0)))

    tbl = Table(
        title=f"[bold red]⚠  Confirmed CVEs affecting installed versions ({len(rows)})[/]",
        title_justify="left", border_style="red",
    )
    tbl.add_column("Plugin", style="bright_white", max_width=30)
    tbl.add_column("Installed", style="cyan", justify="center", max_width=10)
    tbl.add_column("CVE", style="bright_red bold", max_width=18)
    tbl.add_column("Title", style="white", max_width=80)
    tbl.add_column("Severity", justify="center", max_width=10)
    tbl.add_column("CVSS", style="yellow", justify="right", max_width=6)
    tbl.add_column("Fixed In", style="green", justify="center", max_width=14)

    for r in rows:
        sev = r["severity"] or "?"
        sev_color = {"CRITICAL": "bold red", "HIGH": "red",
                     "MEDIUM": "yellow", "LOW": "cyan"}.get(sev, "dim")
        cvss = f"{r['cvss']:.1f}" if isinstance(r["cvss"], (int, float)) else "?"
        tbl.add_row(
            r["plugin"], r["installed"], r["cve"], r["title"],
            f"[{sev_color}]{sev}[/]", cvss,
            f"{r['fixed_in']} [dim]*[/]",
        )
    console.print("[dim]  * fixed-in version from WPVulnerability.net API — "
                  "may reflect group fix, verify per-CVE on CVE.org[/]")
    console.print(tbl)


def render_historical(plugins):
    hist = [p for p in plugins if p.get("historical_vulnerabilities")]
    if not hist:
        return
    console.print("\n[dim]  Historical CVEs (versions not detectable — cannot confirm if affecting):[/]")
    tbl = Table(border_style="dim yellow")
    tbl.add_column("Plugin", style="dim", max_width=60)
    tbl.add_column("Hist. CVEs", style="yellow", justify="right", max_width=12)
    tbl.add_column("Note", style="dim", max_width=36)
    for p in hist:
        meta = p.get("meta") or {}
        name = _clean(meta.get("name")) or p["slug"]
        tbl.add_row(name, str(len(p["historical_vulnerabilities"])),
                    "upgrade to check current status")
    console.print(tbl)


def render_domain(dom):
    if not dom or not dom.get("available"):
        reason = (dom or {}).get("reason", "unavailable")
        console.print(Panel(
            f"[dim]Domain intelligence unavailable — {reason}[/]",
            title="[bold bright_cyan]◆  Domain[/]",
            title_align="left", border_style="dim cyan",
            padding=(0, 1),
        ))
        return
    lines = [
        f"[bright_cyan]Registrar :[/] {dom.get('registrar') or '?'}",
        f"[bright_cyan]Created   :[/] {dom.get('created') or '?'}",
        f"[bright_cyan]Age       :[/] {dom.get('age_years') or '?'} years",
        f"[bright_cyan]Expires   :[/] {dom.get('expires') or '?'}",
        f"[bright_cyan]NS        :[/] {', '.join(dom.get('nameservers', [])[:3])}",
    ]
    console.print(Panel("\n".join(lines),
                        title="[bold bright_cyan]◆  Domain[/]",
                        title_align="left", border_style="bright_cyan",
                        padding=(0, 1)))


def render_features(feat):
    lines = [
        f"[bright_cyan]XML-RPC  :[/] "
        f"{'[yellow]enabled[/]' if feat['xmlrpc']['enabled'] else '[dim]disabled[/]'}",
        f"[bright_cyan]REST API :[/] "
        f"{'[green]enabled[/]' if feat['rest_api']['enabled'] else '[dim]disabled[/]'}",
    ]
    if feat["rest_api"].get("namespaces"):
        lines.append(f"[dim]  namespaces: "
                     f"{', '.join(feat['rest_api']['namespaces'][:6])}[/]")
    console.print(Panel("\n".join(lines),
                        title="[bold bright_cyan]◆  Features[/]",
                        title_align="left", border_style="bright_cyan",
                        padding=(0, 1)))


def export_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    return path

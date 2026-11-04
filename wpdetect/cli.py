#!/usr/bin/env python3
# WP-DETECT — SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-DETECT CLI — badass logs + HTML report."""
import argparse
import sys
import time
from datetime import datetime

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from . import __version__, TOOL_NAME
from .scope import load_scope, enforce, OutOfScopeError
from .scan import Scanner
from .enumerate import Enumerator, dedupe_plugins, check_version_sanity_batch
from .vuln import VulnMatcher
from . import domain, htmlreport
from .report import (
    render_detection, render_tech_stack, render_plugins,
    render_themes, render_vulns, render_historical, render_domain,
    render_features, export_json, console,
)
from .ui import (
    log_info, log_success, log_warn, log_error,
    log_step, log_divider, spinner_status,
)

LOGO = r"""
             _,oooooooooo._.             
         _od88888888888888888o..         
      ,o8888PP"'''     ''"YP8888o.       
    ,o888P''  +---------+    `Y888b.     
   ,888P'     |WP-DETECT|       `Y88L    
  d88P'       +---------+         `88b.  
 d88'                      _oo.    '88b  
,88P    oooooo   oooooo   d8888     `88b 
d8P      `888.    `888.   Y8888      Y88.
88[       `888.   .8888.   `PP       '88[
88[        `888  .8'`888. .8'         88[
Y8b         `888.8'  `888.8'         J88'
]88.         `888'    `888'         ,d8P 
 Y88.         `8'      `8'          d88' 
  Y88.                            ,d88'  
   Y88b.       //////////       ,o88P'   
    `Y88b._    //DEDSEC//    ,,o888P     
      `Y888bo._//////////_,oo8888P'      
        `"Y888888booooo8888888P'         
           ''"YPY8888888PP"''            
"""


def banner():
    art = Text(LOGO, style="bold bright_cyan")
    tag = Text.assemble(
        ("  wordpress plugin & vulnerability detector", "bold white"), "\n",
        ("  stack · plugins · themes · CVEs · domain", "dim cyan"), "\n",
        ("  by ", "dim"), ("DEDSEC", "bold bright_cyan"),
        (" ·   ", "dim"), (f"v{__version__}", "bright_yellow"),
    )
    console.print()
    console.print(Panel(Align.center(Text.assemble(art, "\n", tag)),
                        border_style="bright_cyan", padding=(0, 2)))
    console.print()

def cmd_scan(args):
    banner()

    scan_started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Scope
    scope_path = args.scope or "scope.txt"
    try:
        scope_hosts = load_scope(scope_path)
        host = enforce(args.url, scope_hosts)
    except OutOfScopeError as e:
        log_error(str(e))
        return 2

    log_info(f"Target  : [bold white]{args.url}[/]")
    log_info(f"Scope   : [bold green]{host}[/] — [green]VERIFIED[/]")
    log_info(f"Mode    : [bold cyan]{args.mode}[/]  ·  Workers: [bold]{args.workers}[/]")
    log_divider()
    console.print()

    # ── 1. Detection ─────────────────────────────────────────
    log_step(1, 6, "Detecting WordPress...")
    t0 = time.time()
    with spinner_status("probing homepage, wp-json, feed, readme, login..."):
        scanner = Scanner(args.url, timeout=args.timeout)
        info = scanner.run()
    if not info["is_wordpress"]:
        log_error("Target does not appear to be WordPress")
        return 0
    log_success(f"WordPress [bold]{info.get('version')}[/] detected "
                f"[dim]({time.time() - t0:.1f}s)[/]")
    render_detection(info)

    # ── 2. Tech stack ────────────────────────────────────────
    console.print()
    log_step(2, 6, "Fingerprinting tech stack (Wappalyzer)...")
    t0 = time.time()
    with spinner_status("analyzing 1,400+ fingerprints..."):
        tech = scanner.tech_stack()
    n_tech = len(tech) if isinstance(tech, dict) else 0
    log_success(f"{n_tech} technologies identified [dim]({time.time() - t0:.1f}s)[/]")
    render_tech_stack(tech)

    # ── 3. Enumeration ───────────────────────────────────────
    console.print()
    log_step(3, 6, "Enumerating plugins & themes...")
    en = Enumerator(args.url, scanner.session,
                    timeout=args.timeout, max_workers=args.workers)
    t0 = time.time()
    if args.mode == "passive":
        with spinner_status("parsing HTML assets..."):
            plugins = en.passive()
    elif args.mode == "rest":
        with spinner_status("querying REST namespaces..."):
            plugins = en.rest_api()
    elif args.mode == "aggressive":
        with spinner_status("probing plugin directories..."):
            plugins = en.aggressive(args.slugs or [])
    else:
        with spinner_status("passive HTML + REST namespaces..."):
            plugins = en.hybrid(
                aggressive_slugs=args.slugs if args.aggressive else None,
                probe_readme=(args.aggressive and not args.fast),
            )
    log_success(f"{len(plugins)} plugins detected [dim]({time.time() - t0:.1f}s)[/]")

    t0 = time.time()
    with spinner_status("parsing theme assets..."):
        themes = en.themes_passive()
    log_success(f"{len(themes)} themes detected [dim]({time.time() - t0:.1f}s)[/]")

    # Enrichment + dedupe + version sanity
    if plugins:
        t0 = time.time()
        with spinner_status("fetching WordPress.org metadata (plugins)..."):
            en.enrich_plugins_parallel(plugins)
        log_info(f"  WordPress.org plugin metadata [dim]({time.time() - t0:.1f}s)[/]")

        with spinner_status("deduplicating aliased plugins..."):
            plugins = dedupe_plugins(plugins)
        log_info(f"  → {len(plugins)} unique plugins after dedupe")

        with spinner_status("validating detected versions..."):
            check_version_sanity_batch(plugins)

    if themes:
        t0 = time.time()
        with spinner_status("fetching WordPress.org metadata (themes)..."):
            en.enrich_themes_parallel(themes)
        with spinner_status("deduplicating themes..."):
            themes = dedupe_plugins(themes)
        log_info(f"  {len(themes)} themes enriched [dim]({time.time() - t0:.1f}s)[/]")

    # ── 4. Vulnerabilities ───────────────────────────────────
    console.print()
    log_step(4, 6, "Matching CVEs (version-filtered)...")
    matcher = VulnMatcher(
        timeout=args.timeout, max_workers=args.workers,
        debug=args.debug_api,
    )
    t0 = time.time()
    with spinner_status("querying wpvulnerability.net for each plugin..."):
        matcher.enrich(plugins)
    vulnerable = [p for p in plugins if p.get("vulnerabilities")]
    n_hist_plugins = [p for p in plugins if p.get("historical_vulnerabilities")]
    log_success(
        f"{len(vulnerable)} plugins with [bold red]confirmed[/] CVEs · "
        f"{len(n_hist_plugins)} with historical · "
        f"[dim]({time.time() - t0:.1f}s)[/]"
    )

    t0 = time.time()
    with spinner_status("checking WordPress core..."):
        core_vulns = matcher.lookup_core(info.get("version"))
    if core_vulns:
        log_warn(f"Core: [bold red]{len(core_vulns)}[/] CVEs affect this version")
    else:
        log_success("Core: no CVEs affect this version")
    console.print()

    # ── 5. Domain ────────────────────────────────────────────
    log_step(5, 6, "Querying domain intelligence (RDAP)...")
    t0 = time.time()
    with spinner_status("looking up registrar, creation date, nameservers..."):
        dom = domain.lookup(host, timeout=args.timeout)
    if dom.get("available"):
        log_success(f"Domain registered {dom.get('age_years')} years ago "
                    f"[dim]({time.time() - t0:.1f}s)[/]")
    else:
        log_warn(f"Domain intelligence unavailable [dim]({time.time() - t0:.1f}s)[/]")

    # ── 6. Render ────────────────────────────────────────────
    console.print()
    log_step(6, 6, "Rendering results...")
    log_divider()
    console.print()
    render_plugins(plugins)
    render_themes(themes)
    if core_vulns:
        render_vulns([{"slug": "wordpress-core",
                       "version": info.get("version"),
                       "meta": {"name": "WordPress Core"},
                       "vulnerabilities": core_vulns}])
    render_vulns(vulnerable)
    render_historical(plugins)
    render_domain(dom)
    render_features(scanner.check_features())

    if args.debug_api:
        log_warn("API debug log:")
        for entry in matcher.get_debug_log():
            console.print(f"[dim]  · {entry['label']}[/]")

    # ── Export JSON + HTML ───────────────────────────────────
    summary = {
        "plugin_count": len(plugins),
        "theme_count": len(themes),
        "vulnerable_plugins": len(vulnerable),
        "vuln_count": sum(len(p.get("vulnerabilities", [])) for p in plugins),
        "core_vulns": len(core_vulns),
        "historical_count": sum(len(p.get("historical_vulnerabilities", []))
                                for p in plugins),
    }

    data = {
        "tool": TOOL_NAME, "version": __version__,
        "target": args.url, "mode": args.mode,
        "scan_time": scan_started,
        "detection": info, "tech_stack": tech,
        "plugins": plugins, "themes": themes,
        "core_vulns": core_vulns, "domain": dom,
        "features": scanner.check_features(),
        "summary": summary,
    }

    console.print()
    log_divider()

    if args.output:
        export_json(args.output, data)
        log_success(f"JSON report  → [bold white]{args.output}[/]")

    if args.html or not args.output:
        html_path = args.html or (args.output.rsplit(".", 1)[0] + ".html"
                                  if args.output and "." in args.output
                                  else "wpdetect_report.html")
        try:
            htmlreport.generate(data, html_path)
            log_success(f"HTML report  → [bold white]{html_path}[/]")
        except Exception as e:
            log_error(f"HTML generation failed: {e}")

    console.print()
    log_success("[bold green]Scan complete.[/] Open the HTML report in your browser.")

    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="wpdetect",
        description=f"{TOOL_NAME} v{__version__} — WordPress stack & vulnerability detector",
    )
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="scan a WordPress target")
    s.add_argument("url", help="target URL (must be in scope file)")
    s.add_argument("--scope", default=None, help="scope file (default: scope.txt)")
    s.add_argument("--mode", choices=["passive", "rest", "aggressive", "hybrid"],
                   default="hybrid")
    s.add_argument("--aggressive", action="store_true")
    s.add_argument("--slugs", nargs="*", default=None)
    s.add_argument("--fast", action="store_true")
    s.add_argument("--workers", type=int, default=10)
    s.add_argument("--timeout", type=float, default=15.0)
    s.add_argument("--debug-api", action="store_true")
    s.add_argument("--output", help="save JSON report")
    s.add_argument("--html", help="save HTML report (default: auto)")
    s.set_defaults(func=cmd_scan)
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        banner()
        build_parser().print_help()
        console.print()
        console.print("[dim]Quick start:[/]")
        console.print("  [white]echo 'example.com' > scope.txt[/]")
        console.print("  [white]wpdetect scan https://example.com[/]")
        console.print()
        console.print("[dim]Outputs:[/]")
        console.print("  [white]--output scan.json[/]   JSON report")
        console.print("  [white]--html report.html[/]   HTML report (styled)")
        return 0
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        build_parser().print_help()
        return 1
    try:
        return args.func(args)
    except KeyboardInterrupt:
        log_warn("interrupted")
        return 130
    except Exception as e:
        log_error(f"{type(e).__name__}: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

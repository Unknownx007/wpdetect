# WP-DETECT — SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate a self-contained HTML report matching the CLI theme."""
import html as _html
from datetime import datetime
from pathlib import Path


def _e(s):
    return _html.escape(str(s or ""))


def _vclass(sev):
    return {"CRITICAL": "sev-critical", "HIGH": "sev-high",
            "MEDIUM": "sev-medium", "LOW": "sev-low"}.get(sev or "", "sev-low")


CSS = """
:root {
  --bg: #081318; --surface: #0f1e26; --surface2: #162b36;
  --border: #21384a; --text: #e8f0f5; --muted: #7d95a8;
  --magenta: #14b8a6; --cyan: #22d3ee; --green: #22c55e;
  --yellow: #f59e0b; --red: #f85149;
  --mono: 'JetBrains Mono','SF Mono','Consolas',monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system,BlinkMacSystemFont,'Inter',sans-serif;
  background: var(--bg); color: var(--text);
  font-size: 14px; line-height: 1.6; padding: 40px 20px;
}
body::before {
  content:''; position:fixed; inset:0; z-index:-1;
  background: radial-gradient(ellipse 60% 50% at 50% -10%,
    rgba(20,184,166,.12), transparent);
}
.wrap { max-width: 1200px; margin: 0 auto; }
header {
  text-align: center; margin-bottom: 40px;
  padding-bottom: 30px; border-bottom: 1px solid var(--border);
}
header .logo {
  font-family: var(--mono); font-size: 13px; letter-spacing: 0.2em;
  color: var(--magenta); margin-bottom: 10px; font-weight: 700;
}
header h1 {
  font-size: 32px; font-weight: 800; letter-spacing: -0.02em;
  background: linear-gradient(135deg, var(--magenta), var(--cyan));
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
}
header .target {
  font-family: var(--mono); color: var(--cyan); margin-top: 8px; font-size: 15px;
}
header .meta {
  color: var(--muted); font-size: 12px; margin-top: 12px;
  font-family: var(--mono);
}
.summary {
  display: grid; grid-template-columns: repeat(auto-fit,minmax(200px,1fr));
  gap: 16px; margin-bottom: 40px;
}
.card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 20px;
  transition: all 0.2s;
}
.card:hover { border-color: var(--magenta); transform: translateY(-2px); }
.card .label {
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em;
  color: var(--muted); font-weight: 700; margin-bottom: 6px;
}
.card .value { font-size: 28px; font-weight: 800; line-height: 1.1; }
.card.critical .value { color: var(--red); }
.card.high .value { color: var(--magenta); }
.card.ok .value { color: var(--green); }
.card.info .value { color: var(--cyan); }
section { margin-bottom: 40px; }
section h2 {
  font-size: 18px; font-weight: 700; margin-bottom: 16px;
  padding-bottom: 10px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px;
}
section h2::before { content: '◆'; color: var(--magenta); font-size: 14px; }
table {
  width: 100%; background: var(--surface); border-collapse: collapse;
  border-radius: 12px; overflow: hidden; font-size: 13px;
}
thead { background: var(--surface2); }
th {
  text-align: left; padding: 12px 14px; font-weight: 700;
  font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
  color: var(--muted); border-bottom: 1px solid var(--border);
}
td { padding: 10px 14px; border-bottom: 1px solid var(--border); }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,95,210,0.04); }
td.mono { font-family: var(--mono); font-size: 12px; }
.cve {
  font-family: var(--mono); font-weight: 700; color: var(--cyan);
  font-size: 12px;
}
.sev {
  display: inline-block; padding: 2px 10px; border-radius: 12px;
  font-size: 10px; font-weight: 800; letter-spacing: 0.05em;
}
.sev-critical { background: rgba(248,81,73,.2); color: var(--red); }
.sev-high { background: rgba(255,95,210,.2); color: var(--magenta); }
.sev-medium { background: rgba(245,158,11,.2); color: var(--yellow); }
.sev-low { background: rgba(0,240,255,.15); color: var(--cyan); }
.cvss {
  display: inline-block; min-width: 32px; text-align: center;
  padding: 2px 6px; border-radius: 4px; background: var(--surface2);
  font-family: var(--mono); font-weight: 700; font-size: 11px;
}
.badge-hist {
  display: inline-block; padding: 2px 8px; border-radius: 10px;
  background: rgba(245,158,11,.15); color: var(--yellow);
  font-size: 10px; font-weight: 700;
}
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
@media (max-width: 700px) { .grid2 { grid-template-columns: 1fr; } }
.kv { background: var(--surface); border: 1px solid var(--border);
      border-radius: 12px; padding: 16px 20px; }
.kv .row { display: flex; padding: 6px 0; border-bottom: 1px solid var(--border); }
.kv .row:last-child { border-bottom: none; }
.kv .k { color: var(--muted); font-weight: 700; min-width: 140px;
         font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
.kv .v { color: var(--text); font-family: var(--mono); font-size: 12px; }
.tech-tag {
  display: inline-block; padding: 3px 9px; margin: 2px 4px 2px 0;
  background: var(--surface2); border: 1px solid var(--border);
  border-radius: 6px; font-size: 11px; font-family: var(--mono);
  color: var(--cyan);
}
.tag-parent { color: var(--magenta); }
footer {
  margin-top: 60px; padding-top: 24px;
  border-top: 1px solid var(--border);
  text-align: center; color: var(--muted); font-size: 12px;
  font-family: var(--mono);
}
footer a { color: var(--magenta); text-decoration: none; }
.no-vulns {
  background: rgba(63,185,80,.08); border: 1px solid rgba(63,185,80,.3);
  border-radius: 12px; padding: 20px; text-align: center;
  color: var(--green); font-weight: 600;
}
"""


def generate(data, out_path):
    """Build HTML report from the scan.json dict."""
    target = data.get("target", "?")
    scan_time = data.get("scan_time") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tool_version = data.get("version", "?")
    detection = data.get("detection", {})
    tech = data.get("tech_stack", {})
    plugins = data.get("plugins", [])
    themes = data.get("themes", [])
    core_vulns = data.get("core_vulns", [])
    dom = data.get("domain", {})
    features = data.get("features", {})

    # Compute totals
    all_confirmed = []
    for p in plugins:
        for v in p.get("vulnerabilities", []):
            all_confirmed.append({"plugin": p, "vuln": v})
    for v in core_vulns:
        all_confirmed.append({"plugin": {"slug": "wordpress-core",
                                         "meta": {"name": "WordPress Core"},
                                         "version": detection.get("version")},
                              "vuln": v})

    n_plugins = len(plugins)
    n_themes = len(themes)
    n_confirmed = len(all_confirmed)
    n_critical = sum(1 for c in all_confirmed
                     if (c["vuln"].get("severity") or "").upper() == "CRITICAL")
    n_historical = sum(len(p.get("historical_vulnerabilities", []))
                       for p in plugins)

    # HTML parts
    parts = []
    parts.append(f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP-DETECT — {_e(target)}</title>
<style>{CSS}</style>
</head><body><div class="wrap">
<header>
  <div class="logo">◆ WP-DETECT ◆</div>
  <h1>WordPress Security Report</h1>
  <div class="target">{_e(target)}</div>
  <div class="meta">Scanned {_e(scan_time)} · WP-DETECT v{_e(tool_version)} · by DEDSEC</div>
</header>""")

    # Summary cards
    parts.append('<div class="summary">')
    cms_ver = detection.get("version") or "?"
    parts.append(f'<div class="card info"><div class="label">CMS</div>'
                 f'<div class="value">WP {_e(cms_ver)}</div></div>')
    conf = "HIGH" if len(detection.get("version_sources", [])) >= 2 else "LOW"
    parts.append(f'<div class="card info"><div class="label">Confidence</div>'
                 f'<div class="value">{conf}</div></div>')
    parts.append(f'<div class="card"><div class="label">Plugins</div>'
                 f'<div class="value" style="color:var(--text)">{n_plugins}</div></div>')
    parts.append(f'<div class="card"><div class="label">Themes</div>'
                 f'<div class="value" style="color:var(--text)">{n_themes}</div></div>')
    if n_confirmed:
        cls = "critical" if n_critical else "high"
        parts.append(f'<div class="card {cls}"><div class="label">Confirmed CVEs</div>'
                     f'<div class="value">{n_confirmed}</div></div>')
    else:
        parts.append(f'<div class="card ok"><div class="label">Confirmed CVEs</div>'
                     f'<div class="value">0</div></div>')
    if n_historical:
        parts.append(f'<div class="card"><div class="label">Historical CVEs</div>'
                     f'<div class="value" style="color:var(--yellow)">{n_historical}</div></div>')
    parts.append('</div>')

    # CMS Detection
    parts.append('<section><h2>CMS Detection</h2><div class="kv">')
    parts.append(f'<div class="row"><span class="k">WordPress</span><span class="v" style="color:var(--green)">yes</span></div>')
    parts.append(f'<div class="row"><span class="k">Version</span><span class="v">{_e(cms_ver)}</span></div>')
    parts.append(f'<div class="row"><span class="k">Confidence</span><span class="v">{conf}</span></div>')
    for e in detection.get("evidence", [])[:6]:
        parts.append(f'<div class="row"><span class="k">Evidence</span><span class="v">{_e(e)}</span></div>')
    parts.append('</div></section>')

    # Tech Stack
    if tech and not tech.get("error"):
        groups = {}
        for name, tdata in tech.items():
            for cat in tdata.get("categories", ["Other"]):
                versions = tdata.get("versions", [])
                ver = f" v{versions[0]}" if versions else ""
                groups.setdefault(cat, []).append(f"{name}{ver}")
        parts.append('<section><h2>Technology Stack</h2><div class="kv">')
        for cat in sorted(groups):
            tags = "".join(f'<span class="tech-tag">{_e(t)}</span>'
                           for t in sorted(groups[cat]))
            parts.append(f'<div class="row"><span class="k">{_e(cat)}</span>'
                         f'<span class="v">{tags}</span></div>')
        parts.append('</div></section>')

    # Plugins table
    parts.append('<section><h2>Plugins</h2><table>'
                 '<thead><tr><th>Plugin</th><th>Installed → Latest</th>'
                 '<th>CVEs</th><th>Author</th></tr></thead><tbody>')
    for p in sorted(plugins,
                    key=lambda x: -len(x.get("vulnerabilities", []))):
        meta = p.get("meta") or {}
        name = _e(meta.get("name") or p["slug"])
        author = _e(meta.get("author") or "—")
        installed = p.get("version") or "not detectable"
        latest = meta.get("latest_version")
        if installed in ("not detectable", None):
            ver_cell = f'<span style="color:var(--muted)">{_e(installed)}</span>'
        elif latest and latest != installed:
            ver_cell = (f'<span style="color:var(--text)">{_e(installed)}</span> '
                        f'<span style="color:var(--yellow)">→</span> '
                        f'<span style="color:var(--green)">{_e(latest)}</span>')
        else:
            ver_cell = f'<span style="color:var(--text)">{_e(installed)}</span>'
        n_aff = len(p.get("vulnerabilities", []))
        n_hist = len(p.get("historical_vulnerabilities", []))
        if n_aff:
            cve_cell = f'<span style="color:var(--red);font-weight:800">{n_aff}</span>'
        elif n_hist:
            cve_cell = f'<span class="badge-hist">{n_hist} hist.</span>'
        else:
            cve_cell = '<span style="color:var(--muted)">0</span>'
        parts.append(f'<tr><td>{name}</td><td class="mono">{ver_cell}</td>'
                     f'<td style="text-align:center">{cve_cell}</td>'
                     f'<td style="color:var(--muted)">{author}</td></tr>')
    parts.append('</tbody></table></section>')

    # Confirmed CVEs
    parts.append('<section><h2>Confirmed CVEs (affecting installed versions)</h2>')
    if not all_confirmed:
        parts.append('<div class="no-vulns">✓ No confirmed vulnerabilities affecting installed versions</div>')
    else:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_confirmed.sort(key=lambda c: (
            order.get((c["vuln"].get("severity") or "").upper(), 4),
            -(c["vuln"].get("cvss") or 0)))
        parts.append('<table><thead><tr>'
                     '<th>Plugin</th><th>Installed</th><th>CVE</th>'
                     '<th>Title</th><th>Severity</th><th>CVSS</th>'
                     '<th>Fixed In</th></tr></thead><tbody>')
        for item in all_confirmed:
            v = item["vuln"]
            p = item["plugin"]
            sev = (v.get("severity") or "?").upper()
            cvss = v.get("cvss")
            cvss_s = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else "?"
            pname = _e((p.get("meta") or {}).get("name") or p["slug"])
            parts.append(
                f'<tr>'
                f'<td>{pname}</td>'
                f'<td class="mono">{_e(p.get("version") or "?")}</td>'
                f'<td class="cve">{_e(v.get("cve") or "N/A")}</td>'
                f'<td>{_e(v.get("title") or "")}</td>'
                f'<td><span class="sev {_vclass(sev)}">{_e(sev)}</span></td>'
                f'<td><span class="cvss">{_e(cvss_s)}</span></td>'
                f'<td class="mono" style="color:var(--green)">{_e(v.get("fixed_in") or "?")}</td>'
                f'</tr>'
            )
        parts.append('</tbody></table>')
    parts.append('</section>')

    # Historical CVEs
    hist_plugins = [p for p in plugins if p.get("historical_vulnerabilities")]
    if hist_plugins:
        parts.append('<section><h2>Historical CVEs (versions not detectable)</h2>'
                     '<table><thead><tr><th>Plugin</th><th>Historical CVEs</th>'
                     '<th>Note</th></tr></thead><tbody>')
        for p in hist_plugins:
            meta = p.get("meta") or {}
            name = _e(meta.get("name") or p["slug"])
            n = len(p["historical_vulnerabilities"])
            parts.append(f'<tr><td>{name}</td>'
                         f'<td><span class="badge-hist">{n}</span></td>'
                         f'<td style="color:var(--muted)">upgrade to verify current status</td></tr>')
        parts.append('</tbody></table></section>')

    # Themes
    if themes:
        parts.append('<section><h2>Themes</h2><table>'
                     '<thead><tr><th>Theme</th><th>Installed → Latest</th>'
                     '<th>Parent</th><th>Author</th></tr></thead><tbody>')
        for t in themes:
            meta = t.get("meta") or {}
            name = _e(meta.get("name") or t["slug"])
            installed = t.get("version") or "not detectable"
            latest = meta.get("latest_version")
            if installed in ("not detectable", None):
                ver_cell = f'<span style="color:var(--muted)">not detectable</span>'
            elif latest and latest != installed:
                ver_cell = (f'<span style="color:var(--text)">{_e(installed)}</span> '
                            f'<span style="color:var(--yellow)">→</span> '
                            f'<span style="color:var(--green)">{_e(latest)}</span>')
            else:
                ver_cell = f'<span style="color:var(--text)">{_e(installed)}</span>'
            parent = _e(meta.get("parent") or "—")
            author = _e(meta.get("author") or "—")
            parts.append(f'<tr><td>{name}</td><td class="mono">{ver_cell}</td>'
                         f'<td class="mono">{parent}</td>'
                         f'<td style="color:var(--muted)">{author}</td></tr>')
        parts.append('</tbody></table></section>')

    # Domain
    parts.append('<section><h2>Domain Intelligence</h2>')
    if dom and dom.get("available"):
        parts.append('<div class="grid2">'
                     '<div class="kv">'
                     f'<div class="row"><span class="k">Registrar</span>'
                     f'<span class="v">{_e(dom.get("registrar") or "?")}</span></div>'
                     f'<div class="row"><span class="k">Created</span>'
                     f'<span class="v">{_e(dom.get("created") or "?")}</span></div>'
                     f'<div class="row"><span class="k">Expires</span>'
                     f'<span class="v">{_e(dom.get("expires") or "?")}</span></div>'
                     '</div>'
                     '<div class="kv">'
                     f'<div class="row"><span class="k">Age</span>'
                     f'<span class="v">{_e(dom.get("age_years") or "?")} years</span></div>'
                     f'<div class="row"><span class="k">Nameservers</span>'
                     f'<span class="v">{_e(", ".join(dom.get("nameservers", [])[:3]))}</span></div>'
                     '</div></div>')
    else:
        parts.append('<div class="kv"><div class="row"><span class="k">Status</span>'
                     '<span class="v">unavailable (RDAP rate-limited)</span></div></div>')
    parts.append('</section>')

    # Features
    if features:
        parts.append('<section><h2>Attack Surface</h2><div class="grid2">'
                     '<div class="kv">')
        xmlrpc = features.get("xmlrpc", {}).get("enabled", False)
        rest = features.get("rest_api", {}).get("enabled", False)
        parts.append(f'<div class="row"><span class="k">XML-RPC</span>'
                     f'<span class="v" style="color:{"var(--yellow)" if xmlrpc else "var(--muted)"}">'
                     f'{"enabled" if xmlrpc else "disabled"}</span></div>')
        parts.append(f'<div class="row"><span class="k">REST API</span>'
                     f'<span class="v" style="color:{"var(--green)" if rest else "var(--muted)"}">'
                     f'{"enabled" if rest else "disabled"}</span></div>')
        parts.append('</div></div></section>')

    # Footer
    parts.append(f'''
<footer>
  Generated by <a href="https://github.com/Unknownx007/wp-detect">WP-DETECT</a> v{_e(tool_version)} · by DEDSEC<br>
  Report generated at {_e(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}
</footer>
</div></body></html>''')

    Path(out_path).write_text("".join(parts), encoding="utf-8")
    return out_path

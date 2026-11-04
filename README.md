<div align="center">

<img width="920" height="422" alt="1" src="https://github.com/user-attachments/assets/b3850cfc-b573-4cc7-9cc8-c8a6d2588223" />

# WP-DETECT

**WordPress plugin & vulnerability detector — CLI alternative to detectwpplugin.com**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Author](https://img.shields.io/badge/author-DEDSEC-brightgreen.svg)](https://github.com/Unknownx007)

*stack · plugins · themes · CVEs · domain*

</div>

---

## 📌 What is WP-DETECT?

A **read-only** WordPress security scanner that answers the question every pentester asks first: *"What's on this WordPress site, and what's vulnerable?"*

Point it at a domain you're authorized to test, and it returns:

- **CMS version** — detected via 5 independent fingerprinting methods
- **Plugins** — discovered through passive HTML parsing, REST API namespaces, and optional aggressive directory probing
- **Themes** — with parent/child relationships pulled from WordPress.org
- **Tech stack** — hosting, CDN, page builders, analytics, JS libraries (via Wappalyzer's 1,400+ fingerprints)
- **CVEs** — matched against the **installed version only**, not the full historical list
- **Domain intel** — registrar, creation date, nameservers
- **Attack surface** — XML-RPC state, REST API namespaces, login panel exposure

Output is a **colorized CLI table**, a **professional dark-themed HTML report**, and a **machine-readable JSON file**.

---

## ⚠️ What it does NOT do

WP-DETECT is a **scanner**, not an exploitation tool:

- ❌ Does not exploit any CVE
- ❌ Does not brute-force credentials
- ❌ Does not bypass authentication
- ❌ Does not modify target sites
- ❌ Does not write to any database

It sits in the same category as **WPScan**, **Nuclei detection templates**, and **detectwpplugin.com** — read-only reconnaissance, not attack.

---

## ✨ Features

### Detection
- **Multi-source version detection** — meta generator, RSS feed, `readme.html`, asset `?ver=` params, REST API fingerprint
- **Confidence scoring** — "high" when ≥2 sources agree
- **False positive filtering** — recognizes WordPress core namespaces (`wp`, `oembed`, `batch`, etc.) and excludes them from plugin results

### Enumeration
- **Passive mode** — parses HTML from `/`, `/wp-login.php`, `/feed/`, `/contact/`, `/blog/`, and more
- **REST API mode** — extracts plugin slugs from REST namespace names (`contact-form-7/v1` → `contact-form-7`)
- **Aggressive mode** — probes `/wp-content/plugins/<slug>/readme.txt` for each candidate
- **Hybrid mode** (default) — combines all three for maximum coverage
- **Slug aliasing** — correctly maps `rankmath` → `seo-by-rank-math`, `litespeed` → `litespeed-cache`, `joinchat` → `creame-whatsapp-me`
- **Deduplication** — merges duplicate discoveries into one clean row

### Vulnerability matching
- **Version-filtered CVEs** — only shows CVEs that *actually affect the installed version*
- **Historical CVEs separated** — when version can't be detected, all historical CVEs are shown in a **separate "informational" table**, clearly labelled as "not confirmed"
- **Real CVSS scores** — extracted from `impact.cvss3.score` in the API response
- **Severity chips** — CRITICAL / HIGH / MEDIUM / LOW with color coding
- **Fixed-in version** — shows the release that patches each CVE

### Version accuracy
- **Internal asset filtering** — if a detected version is a full major ahead of the WordPress.org latest (e.g. `5.48.0` vs `4.3.6`), the tool flags it as `"internal asset 5.48.0 (WP.org latest: 4.3.6)"` instead of showing a wrong number
- **Update tracking** — shows `installed → latest` with an arrow when an update is available

### UX
- **Timestamped logs** — `[22:53:45] [+] WordPress 7.1.4 detected (7.1s)`
- **Live spinners** — animated `dots12` spinner during each phase
- **Per-phase timing** — every step shows its duration
- **Parallel fetching** — 8 pages fetched concurrently, 10 parallel workers for enrichment (typically <30s for a full scan, <3s cached)

### Output
- **Colorized CLI tables** — Rich-rendered, terminal-aware
- **Dark HTML report** — self-contained, WordPress-teal themed, ready to hand to a client
- **JSON export** — structured data for CI/CD integration

### Safety
- **Scope enforcement** — refuses to scan domains not listed in `scope.txt`
- **Wildcard support** — `*.example.com` in scope file matches all subdomains
- **Rate-limited** — API requests use a 2-hour cache (`~/.wpdetect/cache/`)

---

## 🚀 Quick Start

```bash
# 1. Clone
git clone https://github.com/Unknownx007/wp-detect.git
cd wp-detect

# 2. Install
python3 -m venv venv
source venv/bin/activate           # Linux / macOS
# venv\Scripts\activate            # Windows
pip install -r requirements.txt

# 3. Authorize your target
echo "example.com" > scope.txt

# 4. Scan
python3 run.py scan https://example.com --output scan.json --html report.html

# 5. Open the HTML report
xdg-open report.html   # Linux
open report.html       # macOS
start report.html      # Windows
```

---

## 📸 Example Output

```
[22:53:45] [*] Target  : https://example.com
[22:53:45] [*] Scope   : example.com — VERIFIED
[22:53:45] [*] Mode    : hybrid  ·  Workers: 10
──────────────────────────────────────────────────────────────────────────────

[22:53:45] [1/6] ▸ Detecting WordPress...
[22:53:52] [+] WordPress 7.1.4 detected (7.1s)
╭─ ◆  CMS Detection ─────────────────────────────────────────╮
│ WordPress : yes                                            │
│ Version   : 7.1.4                                          │
│ Confidence: high                                           │
╰────────────────────────────────────────────────────────────╯

[22:53:52] [2/6] ▸ Fingerprinting tech stack (Wappalyzer)...
[22:53:55] [+] 15 technologies identified (3.4s)

[22:53:55] [3/6] ▸ Enumerating plugins & themes...
[22:54:01] [+] 12 plugins detected (5.4s)
[22:54:02] [+] 2 themes detected (1.8s)
[22:54:03] [*]   WordPress.org plugin metadata (1.2s)
[22:54:04] [*]   → 11 unique plugins after dedupe

[22:54:04] [4/6] ▸ Matching CVEs (version-filtered)...
[22:54:05] [+] 1 plugins with confirmed CVEs · 5 with historical · (0.8s)
[22:54:05] [+] Core: no CVEs affect this version

[22:54:05] [5/6] ▸ Querying domain intelligence...
[22:54:08] [+] Domain registered 22.2 years ago (3.4s)

[22:54:08] [6/6] ▸ Rendering results...
──────────────────────────────────────────────────────────────
```

```
Plugins
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ Plugin                      ┃ Installed → Latest ┃   CVEs    ┃ Author               ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ Jetpack – AI Agents & MCP,  │ 15.8.1 → 16.4      │    3      │ Automattic           │
│ Security, Backup & Analytics│                    │           │                      │
│ Elementor Website Builder   │ not detectable     │ 66 hist.  │ Elementor            │
│ Rank Math SEO               │ not detectable     │ 40 hist.  │ Rank Math SEO        │
│ LiteSpeed Cache             │ not detectable     │ 30 hist.  │ LiteSpeed Tech.      │
└─────────────────────────────┴────────────────────┴───────────┴──────────────────────┘

⚠  Confirmed CVEs affecting installed versions (3)
┏━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━┓
┃ Plugin       ┃Installed┃ CVE             ┃ Title              ┃ Severity ┃ CVSS ┃ Fixed In ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━┩
│ Jetpack      │ 15.8.1  │ CVE-2024-10858  │ Cross-Site Script  │ MEDIUM   │ 6.1  │ 16.1.3*  │
│ Jetpack      │ 15.8.1  │ CVE-2026-106601 │ Auth Bypass        │ MEDIUM   │ 5.4  │ 16.3*    │
│ Jetpack      │ 15.8.1  │ CVE-2026-106602 │ Auth Bypass        │ MEDIUM   │ 4.8  │ 16.3*    │
└──────────────┴─────────┴─────────────────┴────────────────────┴──────────┴──────┴──────────┘
  * fixed-in version from WPVulnerability.net API — may reflect group fix
```

---

## 🛠 CLI Options

```bash
python3 run.py scan <URL> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--scope <file>` | `scope.txt` | Scope file — **required** (see below) |
| `--mode <mode>` | `hybrid` | `passive` / `rest` / `aggressive` / `hybrid` |
| `--aggressive` | off | Enable `readme.txt` probing + custom slug list |
| `--fast` | off | Skip `readme.txt` probes entirely (faster, but may miss versions) |
| `--slugs <slug...>` | — | Custom plugin slugs for aggressive mode |
| `--workers <N>` | `10` | Parallel workers for enrichment |
| `--timeout <sec>` | `15.0` | Per-request HTTP timeout |
| `--debug-api` | off | Show raw API responses (troubleshooting) |
| `--output <file>` | — | Save JSON report |
| `--html <file>` | auto | Save HTML report (default: `wpdetect_report.html`) |

### Examples

```bash
# Full scan with JSON + HTML
python3 run.py scan https://example.com --output scan.json --html report.html

# Fast mode (skip readme probes)
python3 run.py scan https://example.com --fast

# Passive only (HTML parsing — least noise)
python3 run.py scan https://example.com --mode passive

# Aggressive plugin probing
python3 run.py scan https://example.com --mode aggressive --slugs elementor jetpack

# Debug mode
python3 run.py scan https://example.com --debug-api
```

---

## 🔒 Scope File

WP-DETECT **refuses to scan** any domain not listed in `scope.txt`. This is a hard requirement — it protects against accidental unauthorized scanning.

Create `scope.txt` in the same directory you run the tool from:

```
# WP-DETECT scope file
# One authorized domain per line. Wildcards supported (*.example.com).

example.com
www.example.com
staging.example.com
*.internal.example.com
```

Then run:

```bash
python3 run.py scan https://example.com
```

The tool loads `scope.txt` automatically. If the target isn't listed, it exits with:

```
✗ 'unlisted-domain.com' is NOT in scope.txt. Add it explicitly if you
  have written authorization to test it.
```

Override the scope file location:

```bash
python3 run.py scan https://example.com --scope /path/to/my-scope.txt
```

---

## 📊 Data Sources

| Source | Used For | Cost |
|---|---|---|
| **WPVulnerability.net** | Plugin CVE matching (free, no key) | ✅ Free |
| **WordPress.org Plugin API** | Plugin names, authors, latest versions | ✅ Free |
| **WordPress.org Theme API** | Theme names, parents, latest versions | ✅ Free |
| **Wappalyzer** | Tech stack fingerprinting | ✅ Free |
| **RDAP.org / Verisign** | Domain registration data | ✅ Free |
| **whois binary** | Domain fallback (if installed) | ✅ Free |

**No paid APIs, no rate-limited keys, no account needed.** Everything works out of the box.

---

## 📁 Project Structure

```
wp-detect/
├── README.md
├── LICENSE
├── requirements.txt
├── scope.txt.example
├── run.py
├── test_api.py                 ← diagnostic tool for API debugging
└── wpdetect/
    ├── __init__.py
    ├── cli.py                  ← main CLI
    ├── ui.py                   ← timestamped logs + spinners
    ├── scope.py                ← scope enforcement
    ├── scan.py                 ← WordPress detection + tech stack
    ├── enumerate.py            ← plugin/theme enumeration
    ├── vuln.py                 ← CVE matching + version filtering
    ├── domain.py               ← RDAP domain lookup
    ├── report.py               ← Rich CLI rendering
    └── htmlreport.py           ← self-contained HTML report
```

---

## 🧪 Testing

### Built-in API diagnostic

If CVE results look wrong, run the diagnostic to see exactly what the API returns:

```bash
python3 test_api.py jetpack elementor seo-by-rank-math
```

This prints the raw JSON response shape and how the parser interprets it. Useful for:

- Debugging why a plugin shows `0` CVEs
- Verifying the API is reachable
- Confirming the parser handles new response shapes

### Cache management

The tool caches API responses for 2 hours in `~/.wpdetect/cache/`. To force a refresh:

```bash
rm -rf ~/.wpdetect/cache
```

### Verifying results

Cross-check CVE matches against:
- [CVE.org](https://www.cve.org/) — official CVE records
- [Patchstack](https://patchstack.com/database/) — WordPress-specific
- [Wordfence Intelligence](https://www.wordfence.com/threat-intel/) — WordPress-specific

---

## 🛡️ Safety & Ethics

WP-DETECT is designed for **authorized security assessments only**.

### ✅ Permitted uses

- Security audits you are contractually authorized to perform
- CTF challenges and personal labs
- Bug bounty programs where the target is in scope
- Educational study on your own sites
- Vendor security research

### ❌ Not permitted

- Scanning sites you don't own without written authorization
- Scanning competitors or third parties
- Any use violating local computer-misuse laws (CFAA, CMA, GDPR, etc.)

### Recommended workflow

1. **Get written authorization** from the target owner
2. **Add the domain to `scope.txt`** — the tool won't scan without this
3. **Run the scan** at responsible rates (default delays are conservative)
4. **Report findings** to the owner responsibly

Scanning without authorization is illegal in most jurisdictions — even "just checking" the version is a violation.

---

## 🎯 How it compares to detectwpplugin.com

| Feature | detectwpplugin.com | **WP-DETECT** |
|---|---|---|
| WordPress version detection | ✅ | ✅ |
| Plugin detection | ✅ | ✅ |
| Theme detection | ✅ | ✅ |
| Tech stack | ✅ (AI-enhanced) | ✅ (Wappalyzer) |
| **CVE matching** | ✅ | ✅ **version-filtered** |
| **CVSS scores** | ❌ Hidden | ✅ **shown** |
| **Historical vs confirmed separation** | Partial | ✅ **explicit** |
| Domain intelligence | ✅ | ✅ (when available) |
| CLI available | ❌ | ✅ |
| **HTML report export** | ✅ (online only) | ✅ **local file** |
| **JSON export** | ❌ | ✅ |
| **Scope enforcement** | ❌ | ✅ |
| **Rate limit** | 9 free / hour | ✅ **unlimited (cached)** |
| **Requires account** | ✅ | ❌ |
| **Free** | Freemium | ✅ **100% free** |

---

## 🗺 Roadmap

**v1.0** (current)
- ✅ WordPress + version detection
- ✅ Plugin/theme enumeration (3 modes)
- ✅ Version-filtered CVE matching
- ✅ CLI + HTML report
- ✅ Scope enforcement

**v1.1** (planned)
- Domain intel via `ipinfo.io` free tier (fixes current RDAP reliability issue)
- Full CVE titles (no truncation at column width)
- WPScan API as alternative backend
- Better parent-theme detection

**v1.2+**
- Docker container for CI/CD
- GitHub Actions workflow
- WPScan-style password strength detection on login page
- Redirect chain analysis
- Passive subdomain enumeration

---

## 🤝 Contributing

Issues and PRs welcome. For significant changes:

1. Open an issue first to discuss
2. Fork the repo
3. Create a feature branch
4. Submit a PR with a clear description

Areas where help is welcome:
- Additional API backends (Patchstack, Wordfence Intelligence)
- Better version detection heuristics
- More test coverage
- Documentation improvements

---

## 🙏 Credits

- **[WPVulnerability.net](https://www.wpvulnerability.net/)** — free, open vulnerability database
- **[WordPress.org](https://wordpress.org/)** — plugin/theme metadata APIs
- **[Wappalyzer](https://www.wappalyzer.com/)** — tech fingerprinting
- **[Rich](https://github.com/Textualize/rich)** — terminal UI
- **[BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)** — HTML parsing
- Inspired by **[detectwpplugin.com](https://detectwpplugin.com/)** — proving a CLI alternative was worth building

---

## 📜 License

**GNU Affero General Public License v3.0 (AGPL-3.0-or-later)**

```
Copyright (C) 2025 DEDSEC <https://github.com/Unknownx007>
```

You must:
- Keep the copyright notice (`Copyright (C) 2025 DEDSEC`)
- Credit the original author in any redistribution
- Share your source if you distribute or offer this as a network service
- License your fork under AGPLv3

Full text: [LICENSE](LICENSE) · [gnu.org/licenses/agpl-3.0](https://www.gnu.org/licenses/agpl-3.0.html)

---

## 👤 Author

**DEDSEC**

- GitHub: [@Unknownx007](https://github.com/Unknownx007)
- Project: [github.com/Unknownx007/wp-detect](https://github.com/Unknownx007/wp-detect)

---

<div align="center">

**⭐ Star this repo if you find it useful ⭐**

*"Know the WordPress surface before you touch it."*

</div>

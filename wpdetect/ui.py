# WP-DETECT — SPDX-License-Identifier: AGPL-3.0-or-later
"""Timestamped log lines + spinner helpers — teal/cyan theme."""
from datetime import datetime
from rich.console import Console

console = Console(highlight=False, force_terminal=True)


def _ts():
    return datetime.now().strftime("%H:%M:%S")


def log_info(msg):
    console.print(f"[dim]\\[{_ts()}][/] [bright_cyan][*][/] {msg}")


def log_success(msg):
    console.print(f"[dim]\\[{_ts()}][/] [bold green][+][/] {msg}")


def log_warn(msg):
    console.print(f"[dim]\\[{_ts()}][/] [bold yellow][!][/] {msg}")


def log_error(msg):
    console.print(f"[dim]\\[{_ts()}][/] [bold red][-][/] {msg}")


def log_step(step, total, msg):
    console.print(
        f"[dim]\\[{_ts()}][/] [dim]\\[{step}/{total}][/] "
        f"[bold bright_cyan]▸[/] {msg}"
    )


def log_divider():
    console.print(f"[bright_cyan]{'─' * 78}[/]")


def spinner_status(msg, spinner="dots12"):
    """Context manager — animated spinner with message."""
    return console.status(f"[bright_cyan]{msg}[/]", spinner=spinner)

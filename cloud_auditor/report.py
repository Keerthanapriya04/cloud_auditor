"""
Report rendering: pretty terminal output via Rich, plus JSON/YAML export
for CI pipelines, dashboards, or archiving.
"""

import json
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .models import AuditSummary, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}


def render_table(summary: AuditSummary, console: Console) -> None:
    """Print a Rich-formatted summary + detail table to the terminal."""
    if summary.total_findings == 0:
        console.print(Panel.fit(
            "[bold green]✔ No waste or misconfigurations found. Your infrastructure looks clean![/bold green]"
        ))
        return

    table = Table(title="Cloud Infrastructure Audit — Findings", show_lines=False, expand=True)
    table.add_column("Severity", justify="center", no_wrap=True)
    table.add_column("Provider", no_wrap=True)
    table.add_column("Resource Type", no_wrap=True)
    table.add_column("Resource ID", overflow="fold")
    table.add_column("Region", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Est. $/mo", justify="right", no_wrap=True)
    table.add_column("Description", overflow="fold")

    # Sort worst offenders first: severity, then cost
    severity_rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
    sorted_findings = sorted(
        summary.findings,
        key=lambda f: (severity_rank[f.severity], -f.estimated_monthly_cost_usd),
    )

    for f in sorted_findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            Text(f.severity.value, style=color),
            f.provider,
            f.resource_type,
            f.resource_id,
            f.region,
            f.category.value,
            f"${f.estimated_monthly_cost_usd:,.2f}",
            f.description,
        )

    console.print(table)

    summary_panel = Panel.fit(
        f"[bold]{summary.total_findings}[/bold] findings   |   "
        f"[bold green]${summary.total_monthly_savings:,.2f}[/bold green] estimated savings/month   |   "
        f"[bold green]${summary.total_annual_savings:,.2f}[/bold green] estimated savings/year",
        title="Summary",
        border_style="green",
    )
    console.print(summary_panel)

    critical = summary.by_severity(Severity.CRITICAL)
    if critical:
        console.print(
            f"[bold red]⚠ {len(critical)} CRITICAL finding(s) require immediate attention "
            f"(e.g. open security groups).[/bold red]"
        )


def render_cost_breakdown(summary: AuditSummary, console: Console) -> None:
    """Print a secondary table breaking cost down by resource type."""
    if summary.total_findings == 0:
        return
    breakdown = {}
    for f in summary.findings:
        breakdown.setdefault(f.resource_type, {"count": 0, "cost": 0.0})
        breakdown[f.resource_type]["count"] += 1
        breakdown[f.resource_type]["cost"] += f.estimated_monthly_cost_usd

    table = Table(title="Cost Breakdown by Resource Type")
    table.add_column("Resource Type")
    table.add_column("Count", justify="right")
    table.add_column("Est. $/mo", justify="right")

    for rtype, data in sorted(breakdown.items(), key=lambda kv: -kv[1]["cost"]):
        table.add_row(rtype, str(data["count"]), f"${data['cost']:,.2f}")

    console.print(table)


def export_json(summary: AuditSummary, path: str) -> Path:
    out = Path(path)
    out.write_text(json.dumps(summary.to_dict(), indent=2, default=str))
    return out


def export_yaml(summary: AuditSummary, path: str) -> Path:
    out = Path(path)
    out.write_text(yaml.safe_dump(summary.to_dict(), sort_keys=False, default_flow_style=False))
    return out


def export_cleanup_script(summary: AuditSummary, path: str) -> Path:
    """Write all cleanup commands to a shell script, commented out by default
    so the user has to deliberately uncomment/run them (safety-first)."""
    lines = [
        "#!/usr/bin/env bash",
        "# Cloud Infrastructure Auditor — generated cleanup script",
        "# Review EVERY command before running. Lines are commented out by default.",
        "# Uncomment the lines you want to execute, then run: bash cleanup.sh",
        "set -euo pipefail",
        "",
    ]
    for f in summary.findings:
        if f.cleanup_command:
            lines.append(f"# [{f.severity.value}] {f.provider} {f.resource_type} {f.resource_id}")
            lines.append(f"# Reason: {f.description}")
            lines.append(f"# Est. savings: ${f.estimated_monthly_cost_usd:,.2f}/mo")
            lines.append(f"# {f.cleanup_command}")
            lines.append("")
    out = Path(path)
    out.write_text("\n".join(lines))
    out.chmod(0o755)
    return out

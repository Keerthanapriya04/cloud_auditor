"""
Cloud Infrastructure Auditor & Cost Optimizer — CLI entry point.

Usage examples:

    cloud-auditor audit aws --region us-east-1 --region us-west-2
    cloud-auditor audit gcp --project my-gcp-project --zone us-central1-a
    cloud-auditor audit aws --region us-east-1 --output json --output-file report.json
    cloud-auditor cleanup aws --region us-east-1                 # dry-run (default)
    cloud-auditor cleanup aws --region us-east-1 --execute        # actually clean up
    cloud-auditor init-config                                     # write default config.yaml
"""

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console

from .config import load_config, write_default_config
from .models import AuditSummary
from .providers.aws_provider import AWSScanner
from .providers.gcp_provider import GCPScanner
from . import report as report_mod
from .cleanup import execute_cleanup

app = typer.Typer(
    name="cloud-auditor",
    help="Cloud Infrastructure Auditor & Cost Optimizer — find and fix cloud waste on AWS and GCP.",
    add_completion=True,
)
audit_app = typer.Typer(help="Scan cloud accounts for waste and misconfiguration.")
cleanup_app = typer.Typer(help="Clean up flagged resources (dry-run by default).")
app.add_typer(audit_app, name="audit")
app.add_typer(cleanup_app, name="cleanup")

console = Console()


# ----------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------
def _output_results(summary: AuditSummary, output: str, output_file: Optional[str], show_breakdown: bool):
    if output == "table":
        report_mod.render_table(summary, console)
        if show_breakdown:
            report_mod.render_cost_breakdown(summary, console)
    elif output == "json":
        if output_file:
            path = report_mod.export_json(summary, output_file)
            console.print(f"[green]✔ JSON report written to {path}[/green]")
        else:
            import json
            console.print_json(json.dumps(summary.to_dict(), default=str))
    elif output == "yaml":
        if output_file:
            path = report_mod.export_yaml(summary, output_file)
            console.print(f"[green]✔ YAML report written to {path}[/green]")
        else:
            import yaml
            console.print(yaml.safe_dump(summary.to_dict(), sort_keys=False))
    else:
        console.print(f"[red]Unknown output format: {output}[/red]")
        raise typer.Exit(code=1)


# ----------------------------------------------------------------------
# audit aws
# ----------------------------------------------------------------------
@audit_app.command("aws")
def audit_aws(
    region: List[str] = typer.Option(None, "--region", "-r", help="AWS region(s) to scan. Repeatable."),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS named profile to use."),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table | json | yaml"),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-f", help="Write report to this file."),
    config_path: Optional[str] = typer.Option(None, "--config", help="Path to config.yaml."),
    breakdown: bool = typer.Option(True, "--breakdown/--no-breakdown", help="Show cost breakdown table."),
    cleanup_script: Optional[str] = typer.Option(
        None, "--cleanup-script", help="Also write a commented-out cleanup.sh with all fix commands."
    ),
):
    """Scan one or more AWS regions for orphaned/idle/misconfigured resources."""
    config = load_config(config_path)
    regions = region or config["aws"]["regions"]

    all_findings = []
    with console.status("[bold blue]Scanning AWS...", spinner="dots"):
        for r in regions:
            console.log(f"Scanning region: {r}")
            try:
                scanner = AWSScanner(region=r, config=config, console=console, profile=profile)
            except RuntimeError as e:
                console.print(f"[red]{e}[/red]")
                raise typer.Exit(code=1)

            if not scanner.verify_credentials():
                console.print(
                    "[red]✘ Could not authenticate with AWS. Check your credentials "
                    "(env vars, ~/.aws/credentials, or --profile).[/red]"
                )
                raise typer.Exit(code=1)

            all_findings.extend(scanner.scan_all())

    summary = AuditSummary(findings=all_findings)
    _output_results(summary, output, output_file, breakdown)

    if cleanup_script:
        path = report_mod.export_cleanup_script(summary, cleanup_script)
        console.print(f"[green]✔ Cleanup script written to {path}[/green] (all commands commented out)")


# ----------------------------------------------------------------------
# audit gcp
# ----------------------------------------------------------------------
@audit_app.command("gcp")
def audit_gcp(
    project: str = typer.Option(..., "--project", "-p", help="GCP project ID to scan."),
    zone: List[str] = typer.Option(None, "--zone", "-z", help="GCP zone(s) to scan. Repeatable."),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table | json | yaml"),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-f", help="Write report to this file."),
    config_path: Optional[str] = typer.Option(None, "--config", help="Path to config.yaml."),
    breakdown: bool = typer.Option(True, "--breakdown/--no-breakdown", help="Show cost breakdown table."),
    cleanup_script: Optional[str] = typer.Option(
        None, "--cleanup-script", help="Also write a commented-out cleanup.sh with all fix commands."
    ),
):
    """Scan one or more GCP zones for orphaned/idle resources."""
    config = load_config(config_path)
    zones = zone or config["gcp"]["zones"]

    all_findings = []
    with console.status("[bold blue]Scanning GCP...", spinner="dots"):
        for z in zones:
            console.log(f"Scanning zone: {z}")
            try:
                scanner = GCPScanner(project_id=project, zone=z, config=config, console=console)
            except RuntimeError as e:
                console.print(f"[red]{e}[/red]")
                raise typer.Exit(code=1)
            all_findings.extend(scanner.scan_all())

    summary = AuditSummary(findings=all_findings)
    _output_results(summary, output, output_file, breakdown)

    if cleanup_script:
        path = report_mod.export_cleanup_script(summary, cleanup_script)
        console.print(f"[green]✔ Cleanup script written to {path}[/green] (all commands commented out)")


# ----------------------------------------------------------------------
# cleanup aws / gcp
# ----------------------------------------------------------------------
@cleanup_app.command("aws")
def cleanup_aws(
    region: List[str] = typer.Option(None, "--region", "-r", help="AWS region(s) to scan and clean."),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS named profile to use."),
    execute: bool = typer.Option(False, "--execute", help="Actually run cleanup commands (default: dry-run)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-approve every cleanup action (skip per-item prompt)."),
    min_severity: str = typer.Option("LOW", "--min-severity", help="Only clean findings at/above this severity."),
    config_path: Optional[str] = typer.Option(None, "--config", help="Path to config.yaml."),
):
    """Scan AWS, then clean up flagged resources. Dry-run unless --execute is passed."""
    from .models import Severity
    severity_rank = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
    min_rank = severity_rank.get(Severity(min_severity.upper()), 0)

    config = load_config(config_path)
    regions = region or config["aws"]["regions"]

    all_findings = []
    for r in regions:
        scanner = AWSScanner(region=r, config=config, console=console, profile=profile)
        if not scanner.verify_credentials():
            console.print(f"[red]✘ Auth failed for region {r}, skipping.[/red]")
            continue
        all_findings.extend(scanner.scan_all())

    findings = [f for f in all_findings if severity_rank[f.severity] >= min_rank]

    if not findings:
        console.print("[green]No matching findings to clean up.[/green]")
        raise typer.Exit(code=0)

    if not execute:
        console.print("[yellow]DRY-RUN MODE — no changes will be made. Pass --execute to actually run cleanup.[/yellow]\n")

    results = execute_cleanup(findings, execute=execute, console=console, auto_approve=yes)
    console.print(
        f"\n[bold]Done.[/bold] executed={results['executed']} "
        f"skipped={results['skipped']} failed={results['failed']} previewed={results['previewed']}"
    )


@cleanup_app.command("gcp")
def cleanup_gcp(
    project: str = typer.Option(..., "--project", "-p", help="GCP project ID."),
    zone: List[str] = typer.Option(None, "--zone", "-z", help="GCP zone(s) to scan and clean."),
    execute: bool = typer.Option(False, "--execute", help="Actually run cleanup commands (default: dry-run)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-approve every cleanup action."),
    min_severity: str = typer.Option("LOW", "--min-severity", help="Only clean findings at/above this severity."),
    config_path: Optional[str] = typer.Option(None, "--config", help="Path to config.yaml."),
):
    """Scan GCP, then clean up flagged resources. Dry-run unless --execute is passed."""
    from .models import Severity
    severity_rank = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
    min_rank = severity_rank.get(Severity(min_severity.upper()), 0)

    config = load_config(config_path)
    zones = zone or config["gcp"]["zones"]

    all_findings = []
    for z in zones:
        scanner = GCPScanner(project_id=project, zone=z, config=config, console=console)
        all_findings.extend(scanner.scan_all())

    findings = [f for f in all_findings if severity_rank[f.severity] >= min_rank]

    if not findings:
        console.print("[green]No matching findings to clean up.[/green]")
        raise typer.Exit(code=0)

    if not execute:
        console.print("[yellow]DRY-RUN MODE — no changes will be made. Pass --execute to actually run cleanup.[/yellow]\n")

    results = execute_cleanup(findings, execute=execute, console=console, auto_approve=yes)
    console.print(
        f"\n[bold]Done.[/bold] executed={results['executed']} "
        f"skipped={results['skipped']} failed={results['failed']} previewed={results['previewed']}"
    )


# ----------------------------------------------------------------------
# init-config
# ----------------------------------------------------------------------
@app.command("init-config")
def init_config(
    path: Optional[str] = typer.Option(None, "--path", help="Where to write config.yaml (default: ~/.cloud_auditor/config.yaml)."),
):
    """Write out an editable default config.yaml (thresholds, pricing, regions)."""
    written = write_default_config(path)
    console.print(f"[green]✔ Default config written to {written}[/green]")
    console.print("Edit thresholds, pricing, and regions there, then pass --config to point at it if you moved it.")


@app.command("version")
def version():
    """Show the tool version."""
    from . import __version__
    console.print(f"cloud-auditor v{__version__}")


def main():
    app()


if __name__ == "__main__":
    main()

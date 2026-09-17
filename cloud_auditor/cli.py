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
def audit_gcp(
    project: str = typer.Option(..., "--project", "-p", help="GCP project ID to scan."),
    zone: List[str] = typer.Option(None, "--zone", "-z", help="GCP zone(s) to scan. Repeatable."),
    output: str = typer.Option("table", "--output", "-o", help="Output format: table | json | yaml"),
    output_file: Optional[str] = typer.Option(None, "--output-file", "-f", help="Write report to this file."),
    config_path: Optional[str] = typer.Option(None, "--config", help="Path to config.yaml."),
    breakdown: bool = typer.Option(True, "--breakdown/--no-breakdown", help="Show cost breakdown table."),
    cleanup_script: Optional[str] = typer.Option(
        None, "--cleanup-script", help="Also write a commented-out cleanup.sh with all fix commands.")
            ): 

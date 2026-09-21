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


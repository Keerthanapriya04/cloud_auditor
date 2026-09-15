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



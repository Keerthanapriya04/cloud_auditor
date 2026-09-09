import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .models import Finding

AUDIT_LOG_PATH = Path.home() / ".cloud_auditor" / "cleanup_audit.jsonl"


def _log_action(finding: Finding, status: str, detail: str = ""):
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": finding.provider,
        "resource_id": finding.resource_id,
        "resource_type": finding.resource_type,
        "action": finding.cleanup_action,
        "status": status,
        "detail": detail,
    }
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def execute_cleanup(
    findings: List[Finding],
    execute: bool,
    console,
    auto_approve: bool = False,
) -> dict:
    """
    Run through findings and either preview (dry-run) or execute their
    cleanup_command. Returns a summary dict of what happened.
    """
    results = {"executed": 0, "skipped": 0, "failed": 0, "previewed": 0}

    for finding in findings:
        if not finding.cleanup_command:
            continue

        if not execute:
            console.print(
                f"[dim][DRY-RUN][/dim] Would run: [cyan]{finding.cleanup_command}[/cyan]  "
                f"([yellow]{finding.resource_id}[/yellow] — {finding.resource_type})"
            )
            results["previewed"] += 1
            continue

        if not auto_approve:
            confirm = console.input(
                f"[bold]Execute cleanup[/bold] on {finding.provider} {finding.resource_type} "
                f"[yellow]{finding.resource_id}[/yellow]?\n"
                f"  -> {finding.cleanup_command}\n"
                f"  Proceed? [y/N]: "
            )
            if confirm.strip().lower() != "y":
                console.print("  [dim]Skipped.[/dim]")
                results["skipped"] += 1
                _log_action(finding, "skipped")
                continue

        try:
            _run_cleanup_command(finding)
            console.print(f"  [green]✔ Cleaned up {finding.resource_id}[/green]")
            results["executed"] += 1
            _log_action(finding, "executed")
        except Exception as e:  # noqa: BLE001
            console.print(f"  [red]✘ Failed to clean up {finding.resource_id}: {e}[/red]")
            results["failed"] += 1
            _log_action(finding, "failed", detail=str(e))

    return results


def _run_cleanup_command(finding: Finding) -> None:
    """
    Executes the resource's cleanup command.

    For traceability the command is run via the CLI (aws-cli / gcloud) shown
    to the user rather than a hidden SDK call, so `--execute` behaves
    exactly like the command that was printed during dry-run.
    Requires the AWS CLI or gcloud CLI to be installed and authenticated.
    """
    if not finding.cleanup_command:
        raise ValueError("No cleanup command defined for this finding.")

    result = subprocess.run(
        finding.cleanup_command,
        shell=True,
        check=True,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

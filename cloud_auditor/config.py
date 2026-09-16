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


config,py
"""
Configuration loading for the auditor.

Supports a YAML config file (default: ~/.cloud_auditor/config.yaml) that lets
users override CPU/utilization thresholds, rough on-demand pricing used for
cost estimates, and which checks to run. Falls back to sane built-in defaults
so the tool works out of the box with zero configuration.
"""

import os
from pathlib import Path
from typing import Any, Dict

import yaml

DEFAULT_CONFIG_PATH = Path.home() / ".cloud_auditor" / "config.yaml"

# Rough monthly USD estimates used when live pricing APIs aren't queried.
# These are intentionally conservative placeholders -- override via config.yaml
# for accurate figures, or wire up the AWS Pricing API / GCP Billing API.
DEFAULT_CONFIG: Dict[str, Any] = {
    "aws": {
        "regions": ["us-east-1"],
        "idle_cpu_threshold_percent": 5.0,
        "idle_lookback_days": 14,
        "snapshot_stale_days": 90,
        "pricing": {
            "ebs_gp3_per_gb_month": 0.08,
            "ebs_gp2_per_gb_month": 0.10,
            "ebs_io1_per_gb_month": 0.125,
            "elastic_ip_idle_per_month": 3.60,
            "ec2_hourly_fallback": {
                "t3.micro": 0.0104,
                "t3.small": 0.0208,
                "t3.medium": 0.0416,
                "t3.large": 0.0832,
                "m5.large": 0.096,
                "m5.xlarge": 0.192,
                "m5.2xlarge": 0.384,
                "c5.large": 0.085,
                "c5.xlarge": 0.17,
                "r5.large": 0.126,
            },
        },
    },
    "gcp": {
        "zones": ["us-central1-a"],
        "idle_cpu_threshold_percent": 5.0,
        "idle_lookback_days": 14,
        "pricing": {
            "pd_standard_per_gb_month": 0.04,
            "pd_ssd_per_gb_month": 0.17,
            "static_ip_idle_per_month": 7.30,
        },
    },
    "output": {
        "default_format": "table",
    },
}

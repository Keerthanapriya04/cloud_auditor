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


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: str = None) -> Dict[str, Any]:
    """Load config.yaml if present and merge over the built-in defaults."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    if path.exists():
        with open(path, "r") as f:
            user_config = yaml.safe_load(f) or {}
        return _deep_merge(DEFAULT_CONFIG, user_config)
    return DEFAULT_CONFIG


def write_default_config(config_path: str = None) -> Path:
    """Write out the default config file so users can edit it."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.safe_dump(DEFAULT_CONFIG, f, sort_keys=False)
    return path

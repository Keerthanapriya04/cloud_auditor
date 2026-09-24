# Cloud Infrastructure Auditor & Cost Optimizer

A professional CLI for DevOps/FinOps teams to find orphaned, underutilized, or
misconfigured cloud resources on **AWS** and **GCP**, generate a cost-saving
report, and safely clean things up.

## Features

- **AWS checks:** unattached EBS volumes, idle Elastic IPs, idle/oversized EC2
  instances (via CloudWatch CPU metrics), stale EBS snapshots, wide-open
  security groups (0.0.0.0/0 on SSH/RDP/DB ports).
- **GCP checks:** unattached persistent disks, idle reserved static IPs, idle
  Compute Engine instances (via Cloud Monitoring).
- Rich terminal tables with severity color-coding and a cost breakdown.
- JSON / YAML export for CI pipelines or dashboards.
- Safe cleanup: **dry-run by default**, per-resource confirmation, an audit
  trail log, and an optional generated `cleanup.sh` with every fix command
  commented out until you choose to run it.
- Configurable thresholds and pricing via `~/.cloud_auditor/config.yaml`.

## Install

```bash
pip install -r requirements.txt
pip install -e .          # installs the `cloud-auditor` command
```

Or build a standalone binary (no Python needed to run it):

```bash
bash build_binary.sh      # produces dist/cloud-auditor
```

## Authentication

- **AWS:** standard boto3 credential chain — environment variables,
  `~/.aws/credentials`, an IAM role, or `--profile <name>`.
- **GCP:** Application Default Credentials —
  `gcloud auth application-default login`, or set
  `GOOGLE_APPLICATION_CREDENTIALS` to a service account key file.

## Usage

```bash
# Write out an editable config (thresholds, pricing, default regions)
cloud-auditor init-config

# Audit AWS
cloud-auditor audit aws --region us-east-1 --region us-west-2

# Audit AWS, export JSON, and generate a cleanup script
cloud-auditor audit aws --region us-east-1 \
    --output json --output-file report.json \
    --cleanup-script cleanup.sh

# Audit GCP
cloud-auditor audit gcp --project my-gcp-project --zone us-central1-a

# Preview cleanup (dry-run, default)
cloud-auditor cleanup aws --region us-east-1

# Actually run cleanup, only for HIGH+ severity, with per-item confirmation
cloud-auditor cleanup aws --region us-east-1 --execute --min-severity HIGH

# Auto-approve everything (use with care!)
cloud-auditor cleanup aws --region us-east-1 --execute --yes
```

## Required IAM Permissions (AWS)

Read-only audit: `ec2:Describe*`, `cloudwatch:GetMetricStatistics`,
`sts:GetCallerIdentity`.
Cleanup additionally needs: `ec2:DeleteVolume`, `ec2:ReleaseAddress`,
`ec2:StopInstances`, `ec2:DeleteSnapshot`, `ec2:RevokeSecurityGroupIngress`.

## Required IAM Roles (GCP)

Read-only audit: `roles/compute.viewer`, `roles/monitoring.viewer`.
Cleanup additionally needs: `roles/compute.instanceAdmin`.

## Project Layout

```
cloud_auditor/
  cli.py                  # Typer CLI entry point
  config.py                # YAML config loading + defaults
  models.py                 # Finding / AuditSummary dataclasses
  report.py                  # Rich table rendering + JSON/YAML export
  cleanup.py                  # Safe cleanup execution + audit log
  providers/
    aws_provider.py            # boto3-based AWS scanner
    gcp_provider.py             # google-cloud-based GCP scanner
setup.py
requirements.txt
build_binary.sh             # PyInstaller packaging
```

## Safety Notes

- Cleanup is **dry-run by default**. You must pass `--execute` to make
  any change, and confirmation prompts appear per-resource unless `--yes`
  is set.
- All cleanup actions are logged to `~/.cloud_auditor/cleanup_audit.jsonl`.
- Always review a generated `cleanup.sh` before uncommenting and running it.

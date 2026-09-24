#!/usr/bin/env bash
# Build a standalone single-file executable with PyInstaller.
# Output binary: dist/cloud-auditor
set -euo pipefail

pip install -r requirements.txt --break-system-packages
pip install pyinstaller --break-system-packages

pyinstaller \
    --name cloud-auditor \
    --onefile \
    --hidden-import=boto3 \
    --hidden-import=botocore \
    --hidden-import=google.cloud.compute_v1 \
    --hidden-import=google.cloud.monitoring_v3 \
    cloud_auditor/cli.py

echo "Binary built at dist/cloud-auditor"

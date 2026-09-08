from setuptools import setup, find_packages

setup(
    name="cloud-auditor",
    version="1.0.0",
    description="Cloud Infrastructure Auditor & Cost Optimizer for AWS and GCP",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "typer[all]>=0.12.0",
        "rich>=13.7.0",
        "boto3>=1.34.0",
        "botocore>=1.34.0",
        "google-cloud-compute>=1.19.0",
        "google-cloud-monitoring>=2.21.0",
        "PyYAML>=6.0.1",
    ],
    entry_points={
        "console_scripts": [
            "cloud-auditor=cloud_auditor.cli:main",
        ],
    },
)

"""
Shared data models used across providers, report generation, and cleanup.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ResourceCategory(str, Enum):
    ORPHANED = "ORPHANED"          # e.g. unattached volume, unassociated IP
    UNDERUTILIZED = "UNDERUTILIZED"  # e.g. idle/oversized instance
    MISCONFIGURED = "MISCONFIGURED"  # e.g. open security group, no lifecycle policy
    STALE = "STALE"                 # e.g. old snapshots/images


@dataclass
class Finding:
    """A single audit finding representing one wasteful/risky cloud resource."""

    provider: str                      # "AWS" or "GCP"
    resource_id: str                   # e.g. vol-0123456789abcdef0
    resource_type: str                 # e.g. "EBS Volume", "Elastic IP"
    region: str
    category: ResourceCategory
    severity: Severity
    description: str
    estimated_monthly_cost_usd: float = 0.0
    cleanup_action: Optional[str] = None    # human readable action
    cleanup_command: Optional[str] = None   # actual CLI command to fix it
    metadata: dict = field(default_factory=dict)
    detected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        d = {
            "provider": self.provider,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "region": self.region,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "estimated_monthly_cost_usd": round(self.estimated_monthly_cost_usd, 2),
            "cleanup_action": self.cleanup_action,
            "cleanup_command": self.cleanup_command,
            "metadata": self.metadata,
            "detected_at": self.detected_at,
        }
        return d


@dataclass
class AuditSummary:
    """Aggregated results of an audit run."""

    findings: list = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def total_monthly_savings(self) -> float:
        return sum(f.estimated_monthly_cost_usd for f in self.findings)

    @property
    def total_annual_savings(self) -> float:
        return self.total_monthly_savings * 12

    def by_severity(self, severity: Severity) -> list:
        return [f for f in self.findings if f.severity == severity]

    def by_category(self, category: ResourceCategory) -> list:
        return [f for f in self.findings if f.category == category]

    def to_dict(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "estimated_monthly_savings_usd": round(self.total_monthly_savings, 2),
            "estimated_annual_savings_usd": round(self.total_annual_savings, 2),
            "findings": [f.to_dict() for f in self.findings],
        }

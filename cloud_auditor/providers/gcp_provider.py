"""
GCP resource scanner.

Uses the Google Cloud Python client libraries to authenticate (Application
Default Credentials: `gcloud auth application-default login`, a service
account key via GOOGLE_APPLICATION_CREDENTIALS, or workload identity) and
scans Compute Engine resources for waste.

Checks implemented:
  1. Unattached persistent disks       -> ORPHANED
  2. Reserved-but-unused static IPs    -> ORPHANED
  3. Idle Compute Engine instances     -> UNDERUTILIZED (via Cloud Monitoring)

Like the AWS scanner, each check is isolated so one failing API call
(missing permission, API not enabled, etc.) doesn't abort the whole scan.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

try:
    from google.cloud import compute_v1
    from google.cloud import monitoring_v3
    from google.api_core import exceptions as gcp_exceptions
except ImportError:  # pragma: no cover
    compute_v1 = None
    monitoring_v3 = None
    gcp_exceptions = None

from ..models import Finding, Severity, ResourceCategory


class GCPScanner:
    def __init__(self, project_id: str, zone: str, config: dict, console=None):
        if compute_v1 is None:
            raise RuntimeError(
                "google-cloud-compute / google-cloud-monitoring not installed.\n"
                "Run: pip install google-cloud-compute google-cloud-monitoring"
            )
        self.project_id = project_id
        self.zone = zone
        self.region = zone.rsplit("-", 1)[0] if "-" in zone else zone
        self.config = config["gcp"]
        self.console = console

        self.disks_client = compute_v1.DisksClient()
        self.addresses_client = compute_v1.AddressesClient()
        self.instances_client = compute_v1.InstancesClient()
        self.metric_client = monitoring_v3.MetricServiceClient()

    def _warn(self, msg: str):
        if self.console:
            self.console.print(f"[yellow]⚠ GCP[{self.zone}]: {msg}[/yellow]")

    # ------------------------------------------------------------------
    def scan_all(self) -> List[Finding]:
        findings: List[Finding] = []
        for check in (
            self.scan_unattached_disks,
            self.scan_idle_static_ips,
            self.scan_idle_instances,
        ):
            try:
                findings.extend(check())
            except Exception as e:  # noqa: BLE001 - degrade gracefully per-check
                self._warn(f"{check.__name__} failed: {e}")
        return findings

    # ------------------------------------------------------------------
    # 1. Unattached persistent disks
    # ------------------------------------------------------------------
    def scan_unattached_disks(self) -> List[Finding]:
        findings = []
        pricing = self.config["pricing"]
        request = compute_v1.ListDisksRequest(project=self.project_id, zone=self.zone)
        for disk in self.disks_client.list(request=request):
            if not disk.users:  # no instances attached
                size_gb = disk.size_gb
                disk_type = disk.type_.split("/")[-1] if disk.type_ else "pd-standard"
                rate_key = "pd_ssd_per_gb_month" if "ssd" in disk_type else "pd_standard_per_gb_month"
                rate = pricing.get(rate_key, pricing["pd_standard_per_gb_month"])
                monthly_cost = size_gb * rate

                findings.append(Finding(
                    provider="GCP",
                    resource_id=disk.name,
                    resource_type="Persistent Disk",
                    region=self.zone,
                    category=ResourceCategory.ORPHANED,
                    severity=Severity.MEDIUM if monthly_cost < 20 else Severity.HIGH,
                    description=(
                        f"Persistent disk '{disk.name}' ({disk_type}, {size_gb} GiB) "
                        f"is not attached to any instance."
                    ),
                    estimated_monthly_cost_usd=monthly_cost,
                    cleanup_action="Delete unattached disk (snapshot first if unsure)",
                    cleanup_command=f"gcloud compute disks delete {disk.name} --zone={self.zone} --project={self.project_id}",
                    metadata={"size_gb": size_gb, "disk_type": disk_type},
                ))
        return findings

    # ------------------------------------------------------------------
    # 2. Idle reserved static IPs
    # ------------------------------------------------------------------
    def scan_idle_static_ips(self) -> List[Finding]:
        findings = []
        monthly_cost = self.config["pricing"]["static_ip_idle_per_month"]
        request = compute_v1.ListAddressesRequest(project=self.project_id, region=self.region)
        for addr in self.addresses_client.list(request=request):
            if addr.status == "RESERVED":  # RESERVED means not currently in use
                findings.append(Finding(
                    provider="GCP",
                    resource_id=addr.name,
                    resource_type="Static IP Address",
                    region=self.region,
                    category=ResourceCategory.ORPHANED,
                    severity=Severity.LOW,
                    description=(
                        f"Static IP '{addr.name}' ({addr.address}) is reserved but not "
                        f"currently attached to any resource."
                    ),
                    estimated_monthly_cost_usd=monthly_cost,
                    cleanup_action="Release the unused static IP",
                    cleanup_command=f"gcloud compute addresses delete {addr.name} --region={self.region} --project={self.project_id}",
                    metadata={"address": addr.address},
                ))
        return findings

    # ------------------------------------------------------------------
    # 3. Idle Compute Engine instances (via Cloud Monitoring)
    # ------------------------------------------------------------------
    def scan_idle_instances(self) -> List[Finding]:
        findings = []
        threshold = self.config["idle_cpu_threshold_percent"]
        lookback_days = self.config["idle_lookback_days"]

        request = compute_v1.ListInstancesRequest(project=self.project_id, zone=self.zone)
        for instance in self.instances_client.list(request=request):
            if instance.status != "RUNNING":
                continue
            avg_cpu = self._get_average_cpu(instance.id, lookback_days)
            if avg_cpu is None:
                continue
            machine_type = instance.machine_type.split("/")[-1] if instance.machine_type else "unknown"
            # Rough fallback estimate; wire up Cloud Billing Catalog API for exact pricing.
            monthly_cost = 24.0 if "micro" in machine_type or "small" in machine_type else 50.0

            if avg_cpu < threshold:
                findings.append(Finding(
                    provider="GCP",
                    resource_id=instance.name,
                    resource_type="Compute Instance",
                    region=self.zone,
                    category=ResourceCategory.UNDERUTILIZED,
                    severity=Severity.HIGH if monthly_cost > 50 else Severity.MEDIUM,
                    description=(
                        f"Instance '{instance.name}' ({machine_type}) averaged {avg_cpu:.1f}% "
                        f"CPU over the last {lookback_days} days — consider stopping or downsizing."
                    ),
                    estimated_monthly_cost_usd=monthly_cost,
                    cleanup_action="Stop or downsize the idle instance",
                    cleanup_command=f"gcloud compute instances stop {instance.name} --zone={self.zone} --project={self.project_id}",
                    metadata={"machine_type": machine_type, "avg_cpu_percent": round(avg_cpu, 2)},
                ))
        return findings

    def _get_average_cpu(self, instance_id: int, lookback_days: int) -> Optional[float]:
        try:
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=lookback_days)
            interval = monitoring_v3.TimeInterval(
                {
                    "end_time": {"seconds": int(end.timestamp())},
                    "start_time": {"seconds": int(start.timestamp())},
                }
            )
            results = self.metric_client.list_time_series(
                request={
                    "name": f"projects/{self.project_id}",
                    "filter": (
                        'metric.type = "compute.googleapis.com/instance/cpu/utilization" '
                        f'AND resource.labels.instance_id = "{instance_id}"'
                    ),
                    "interval": interval,
                    "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                }
            )
            values = []
            for series in results:
                for point in series.points:
                    values.append(point.value.double_value * 100)  # utilization is 0..1
            if not values:
                return None
            return sum(values) / len(values)
        except Exception:  # noqa: BLE001 - Monitoring API may not be enabled
            return None

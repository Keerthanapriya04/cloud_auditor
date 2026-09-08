"""
AWS resource scanner.

Uses boto3 to authenticate with AWS (via standard credential chain: env vars,
~/.aws/credentials, IAM role, SSO profile, etc.) and scans EC2/EBS resources
for waste and misconfiguration.

Checks implemented:
  1. Unattached EBS volumes            -> ORPHANED
  2. Idle Elastic IPs (not associated) -> ORPHANED
  3. Idle EC2 instances (low CPU)      -> UNDERUTILIZED
  4. Oversized EC2 instances           -> UNDERUTILIZED (heuristic on CPU + type)
  5. Stale EBS snapshots               -> STALE
  6. Wide-open security groups (0.0.0.0/0 on sensitive ports) -> MISCONFIGURED

Each check degrades gracefully: if the AWS API call fails (missing
permission, region not enabled, etc.) the scanner logs a warning via the
supplied `console` and continues with the remaining checks instead of
crashing the whole audit.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
except ImportError:  # pragma: no cover
    boto3 = None

from ..models import Finding, Severity, ResourceCategory

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}


class AWSScanner:
    def __init__(self, region: str, config: dict, console=None, profile: Optional[str] = None):
        if boto3 is None:
            raise RuntimeError(
                "boto3 is not installed. Run: pip install boto3"
            )
        self.region = region
        self.config = config["aws"]
        self.console = console
        session_kwargs = {"region_name": region}
        if profile:
            session_kwargs["profile_name"] = profile
        self.session = boto3.Session(**session_kwargs)
        self.ec2 = self.session.client("ec2")
        self.cloudwatch = self.session.client("cloudwatch")

    def _warn(self, msg: str):
        if self.console:
            self.console.print(f"[yellow]⚠ AWS[{self.region}]: {msg}[/yellow]")

    def verify_credentials(self) -> bool:
        try:
            self.session.client("sts").get_caller_identity()
            return True
        except (NoCredentialsError, ClientError, BotoCoreError) as e:
            self._warn(f"Credential check failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    def scan_all(self) -> List[Finding]:
        findings: List[Finding] = []
        for check in (
            self.scan_unattached_volumes,
            self.scan_idle_elastic_ips,
            self.scan_idle_instances,
            self.scan_stale_snapshots,
            self.scan_open_security_groups,
        ):
            try:
                findings.extend(check())
            except (ClientError, BotoCoreError) as e:
                self._warn(f"{check.__name__} failed: {e}")
        return findings

    # ------------------------------------------------------------------
    # 1. Unattached EBS volumes
    # ------------------------------------------------------------------
    def scan_unattached_volumes(self) -> List[Finding]:
        findings = []
        pricing = self.config["pricing"]
        paginator = self.ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
            for vol in page["Volumes"]:
                vol_id = vol["VolumeId"]
                size_gb = vol["Size"]
                vol_type = vol.get("VolumeType", "gp2")
                rate_key = f"ebs_{vol_type}_per_gb_month"
                rate = pricing.get(rate_key, pricing.get("ebs_gp2_per_gb_month", 0.10))
                monthly_cost = size_gb * rate
                name_tag = next((t["Value"] for t in vol.get("Tags", []) if t["Key"] == "Name"), "")

                findings.append(Finding(
                    provider="AWS",
                    resource_id=vol_id,
                    resource_type="EBS Volume",
                    region=self.region,
                    category=ResourceCategory.ORPHANED,
                    severity=Severity.MEDIUM if monthly_cost < 20 else Severity.HIGH,
                    description=(
                        f"Unattached {vol_type} volume '{name_tag or vol_id}' "
                        f"({size_gb} GiB) has not been attached to any instance."
                    ),
                    estimated_monthly_cost_usd=monthly_cost,
                    cleanup_action="Delete unattached volume (snapshot first if unsure)",
                    cleanup_command=f"aws ec2 delete-volume --volume-id {vol_id} --region {self.region}",
                    metadata={"size_gb": size_gb, "volume_type": vol_type,
                              "availability_zone": vol.get("AvailabilityZone")},
                ))
        return findings

    # ------------------------------------------------------------------
    # 2. Idle Elastic IPs
    # ------------------------------------------------------------------
    def scan_idle_elastic_ips(self) -> List[Finding]:
        findings = []
        monthly_cost = self.config["pricing"]["elastic_ip_idle_per_month"]
        addresses = self.ec2.describe_addresses().get("Addresses", [])
        for addr in addresses:
            if "AssociationId" not in addr and "InstanceId" not in addr:
                alloc_id = addr.get("AllocationId", addr.get("PublicIp"))
                findings.append(Finding(
                    provider="AWS",
                    resource_id=alloc_id,
                    resource_type="Elastic IP",
                    region=self.region,
                    category=ResourceCategory.ORPHANED,
                    severity=Severity.LOW,
                    description=(
                        f"Elastic IP {addr.get('PublicIp')} is allocated but not "
                        f"associated with any running instance or ENI."
                    ),
                    estimated_monthly_cost_usd=monthly_cost,
                    cleanup_action="Release the unused Elastic IP",
                    cleanup_command=f"aws ec2 release-address --allocation-id {alloc_id} --region {self.region}",
                    metadata={"public_ip": addr.get("PublicIp")},
                ))
        return findings

    # ------------------------------------------------------------------
    # 3. Idle / oversized EC2 instances (via CloudWatch avg CPU)
    # ------------------------------------------------------------------
    def scan_idle_instances(self) -> List[Finding]:
        findings = []
        threshold = self.config["idle_cpu_threshold_percent"]
        lookback_days = self.config["idle_lookback_days"]
        hourly_rates = self.config["pricing"]["ec2_hourly_fallback"]

        paginator = self.ec2.get_paginator("describe_instances")
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    instance_id = instance["InstanceId"]
                    instance_type = instance["InstanceType"]
                    avg_cpu = self._get_average_cpu(instance_id, lookback_days)
                    if avg_cpu is None:
                        continue

                    name_tag = next((t["Value"] for t in instance.get("Tags", []) if t["Key"] == "Name"), "")
                    hourly_rate = hourly_rates.get(instance_type, 0.05)
                    monthly_cost = hourly_rate * 730

                    if avg_cpu < threshold:
                        findings.append(Finding(
                            provider="AWS",
                            resource_id=instance_id,
                            resource_type="EC2 Instance",
                            region=self.region,
                            category=ResourceCategory.UNDERUTILIZED,
                            severity=Severity.HIGH if monthly_cost > 50 else Severity.MEDIUM,
                            description=(
                                f"Instance '{name_tag or instance_id}' ({instance_type}) averaged "
                                f"{avg_cpu:.1f}% CPU over the last {lookback_days} days — "
                                f"consider stopping, downsizing, or moving to a smaller type."
                            ),
                            estimated_monthly_cost_usd=monthly_cost,
                            cleanup_action="Stop or downsize the idle instance",
                            cleanup_command=f"aws ec2 stop-instances --instance-ids {instance_id} --region {self.region}",
                            metadata={"instance_type": instance_type, "avg_cpu_percent": round(avg_cpu, 2)},
                        ))
                    elif avg_cpu < threshold * 2 and instance_type.split(".")[1:2] and \
                            any(instance_type.startswith(p) for p in ("m5.2x", "m5.4x", "c5.2x", "c5.4x", "r5.2x", "r5.4x")):
                        # Heuristic: large instance type with modest utilization -> right-sizing candidate
                        findings.append(Finding(
                            provider="AWS",
                            resource_id=instance_id,
                            resource_type="EC2 Instance",
                            region=self.region,
                            category=ResourceCategory.UNDERUTILIZED,
                            severity=Severity.MEDIUM,
                            description=(
                                f"Instance '{name_tag or instance_id}' ({instance_type}) is a large "
                                f"instance type averaging only {avg_cpu:.1f}% CPU — likely oversized "
                                f"for its workload."
                            ),
                            estimated_monthly_cost_usd=monthly_cost * 0.5,  # rough potential savings from downsizing
                            cleanup_action="Right-size to a smaller instance type",
                            cleanup_command=(
                                f"aws ec2 modify-instance-attribute --instance-id {instance_id} "
                                f"--instance-type '{{\"Value\": \"<smaller-type>\"}}' --region {self.region}"
                            ),
                            metadata={"instance_type": instance_type, "avg_cpu_percent": round(avg_cpu, 2)},
                        ))
        return findings

    def _get_average_cpu(self, instance_id: str, lookback_days: int) -> Optional[float]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=lookback_days)
        try:
            resp = self.cloudwatch.get_metric_statistics(
                Namespace="AWS/EC2",
                MetricName="CPUUtilization",
                Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
                StartTime=start,
                EndTime=end,
                Period=3600 * 24,
                Statistics=["Average"],
            )
            datapoints = resp.get("Datapoints", [])
            if not datapoints:
                return None
            return sum(dp["Average"] for dp in datapoints) / len(datapoints)
        except (ClientError, BotoCoreError):
            return None

    # ------------------------------------------------------------------
    # 4. Stale EBS snapshots
    # ------------------------------------------------------------------
    def scan_stale_snapshots(self) -> List[Finding]:
        findings = []
        stale_days = self.config["snapshot_stale_days"]
        cutoff = datetime.now(timezone.utc) - timedelta(days=stale_days)
        # OwnerIds=["self"] restricts to snapshots owned by the current account
        paginator = self.ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page["Snapshots"]:
                start_time = snap["StartTime"]
                if start_time < cutoff:
                    size_gb = snap.get("VolumeSize", 0)
                    monthly_cost = size_gb * 0.05  # rough snapshot storage rate
                    age_days = (datetime.now(timezone.utc) - start_time).days
                    findings.append(Finding(
                        provider="AWS",
                        resource_id=snap["SnapshotId"],
                        resource_type="EBS Snapshot",
                        region=self.region,
                        category=ResourceCategory.STALE,
                        severity=Severity.LOW,
                        description=(
                            f"Snapshot {snap['SnapshotId']} is {age_days} days old "
                            f"(older than the {stale_days}-day threshold) and {size_gb} GiB in size."
                        ),
                        estimated_monthly_cost_usd=monthly_cost,
                        cleanup_action="Review and delete if no longer needed",
                        cleanup_command=f"aws ec2 delete-snapshot --snapshot-id {snap['SnapshotId']} --region {self.region}",
                        metadata={"age_days": age_days, "size_gb": size_gb},
                    ))
        return findings

    # ------------------------------------------------------------------
    # 5. Wide-open security groups
    # ------------------------------------------------------------------
    def scan_open_security_groups(self) -> List[Finding]:
        findings = []
        paginator = self.ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort")
                    for ip_range in perm.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0" and from_port in SENSITIVE_PORTS:
                            service = SENSITIVE_PORTS[from_port]
                            findings.append(Finding(
                                provider="AWS",
                                resource_id=sg["GroupId"],
                                resource_type="Security Group",
                                region=self.region,
                                category=ResourceCategory.MISCONFIGURED,
                                severity=Severity.CRITICAL,
                                description=(
                                    f"Security group '{sg.get('GroupName', sg['GroupId'])}' allows "
                                    f"{service} (port {from_port}) from 0.0.0.0/0 (the entire internet)."
                                ),
                                estimated_monthly_cost_usd=0.0,
                                cleanup_action=f"Restrict port {from_port} to trusted CIDR ranges",
                                cleanup_command=(
                                    f"aws ec2 revoke-security-group-ingress --group-id {sg['GroupId']} "
                                    f"--protocol tcp --port {from_port} --cidr 0.0.0.0/0 --region {self.region}"
                                ),
                                metadata={"port": from_port, "service": service, "group_name": sg.get("GroupName")},
                            ))
        return findings

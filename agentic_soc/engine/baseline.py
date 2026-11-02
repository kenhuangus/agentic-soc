"""Entity baseline modeling and statistical deviation detection."""

from __future__ import annotations
from typing import Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field
from ..models.ocsf import AuthenticationEvent, NetworkActivityEvent, FileActivityEvent, OCSFEvent


class UserBaseline(BaseModel):
    user_id: str
    allowed_subnets: List[str] = Field(default_factory=lambda: ["10.0.0.0/8", "192.168.1.0/24"])
    allowed_countries: List[str] = Field(default_factory=lambda: ["US", "CA"])
    typical_hours_utc: List[int] = Field(default_factory=lambda: list(range(13, 23)))  # 9am-7pm EST
    known_devices: Set[str] = Field(default_factory=set)
    mfa_enforced: bool = True


class HostBaseline(BaseModel):
    host_id: str
    approved_processes: Set[str] = Field(default_factory=lambda: {
        "svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe", "services.exe", "cmd.exe", "powershell.exe"
    })
    known_external_destinations: Set[str] = Field(default_factory=set)
    normal_listening_ports: Set[int] = Field(default_factory=lambda: {80, 443, 22, 3389})


class EntityBaselineStore:
    """In-memory 30-day baseline cache for user and host behavioral analytics."""

    def __init__(self) -> None:
        self.user_baselines: Dict[str, UserBaseline] = {}
        self.host_baselines: Dict[str, HostBaseline] = {}

    def register_user_baseline(self, baseline: UserBaseline) -> None:
        self.user_baselines[baseline.user_id] = baseline

    def register_host_baseline(self, baseline: HostBaseline) -> None:
        self.host_baselines[baseline.host_id] = baseline

    def get_or_create_user(self, user_id: str) -> UserBaseline:
        if user_id not in self.user_baselines:
            self.user_baselines[user_id] = UserBaseline(user_id=user_id)
        return self.user_baselines[user_id]

    def get_or_create_host(self, host_id: str) -> HostBaseline:
        if host_id not in self.host_baselines:
            self.host_baselines[host_id] = HostBaseline(host_id=host_id)
        return self.host_baselines[host_id]

    def evaluate_auth_deviation(self, event: AuthenticationEvent) -> Tuple[float, List[str]]:
        """Evaluates an authentication event against historical baseline. Returns (anomaly_score, deviations)."""
        baseline = self.get_or_create_user(event.principal)
        deviations: List[str] = []
        score = 0.0

        # Check geo country
        if event.src_geo_country and event.src_geo_country not in baseline.allowed_countries:
            deviations.append(f"Anomalous source country: {event.src_geo_country} (Expected: {baseline.allowed_countries})")
            score += 0.35

        # Check IP subnet (simplified check: private vs external)
        is_private = event.src_ip.startswith("10.") or event.src_ip.startswith("192.168.") or event.src_ip.startswith("172.16.")
        if not is_private and "0.0.0.0/0" not in baseline.allowed_subnets:
            deviations.append(f"External untrusted IP address: {event.src_ip}")
            score += 0.25

        # Check MFA requirement
        if baseline.mfa_enforced and not event.mfa_used:
            deviations.append("MFA bypass or missing MFA challenge on sensitive logon")
            score += 0.30

        # Check status failure
        if event.status == "failure":
            deviations.append("Failed authentication attempt")
            score += 0.15

        return min(round(score, 2), 1.0), deviations

    def evaluate_host_deviation(self, event: FileActivityEvent) -> Tuple[float, List[str]]:
        """Evaluates process and file activity against baseline."""
        deviations: List[str] = []
        score = 0.0

        # Check execution of suspicious binaries
        suspicious_names = {"mimikatz.exe", "psexec.exe", "cobaltstrike.exe", "rclone.exe", "certutil.exe", "vssadmin.exe"}
        if event.file_name.lower() in suspicious_names or event.actor_process_name.lower() in suspicious_names:
            deviations.append(f"High-risk security tool or binary detected: {event.file_name or event.actor_process_name}")
            score += 0.60

        # Check suspicious commands
        cmd = event.actor_command_line.lower()
        if "delete shadows" in cmd or "invoke-mimikatz" in cmd or "sekurlsa" in cmd or "downloadstring" in cmd:
            deviations.append(f"Malicious command-line pattern observed: {event.actor_command_line}")
            score += 0.40

        return min(round(score, 2), 1.0), deviations

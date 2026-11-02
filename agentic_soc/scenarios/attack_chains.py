"""Realistic synthetic attack scenarios conforming to OCSF schemas."""

from typing import List, Tuple
from ..models.ocsf import AuthenticationEvent, NetworkActivityEvent, FileActivityEvent, FindingEvent, OCSFEvent
from ..engine.baseline import EntityBaselineStore, UserBaseline, HostBaseline


def generate_false_positive_scenario() -> Tuple[FindingEvent, List[OCSFEvent], EntityBaselineStore]:
    """Generates a benign admin maintenance task that triggers a noisy alert rule."""
    store = EntityBaselineStore()
    user_id = "admin_alice"
    store.register_user_baseline(UserBaseline(
        user_id=user_id,
        allowed_subnets=["10.10.0.0/16"],
        allowed_countries=["US"],
        mfa_enforced=True
    ))

    finding = FindingEvent(
        event_id="FIND-101",
        finding_id="ALERT-NOISY-PS-01",
        rule_name="Unusual PowerShell Command-Line Execution",
        mitre_technique_id="T1059.001",
        description="PowerShell process launched with command-line arguments.",
        confidence_score=0.40,
        entity_id=user_id,
        entity_type="user"
    )

    events: List[OCSFEvent] = [
        AuthenticationEvent(
            event_id="AUTH-001",
            principal=user_id,
            src_ip="10.10.4.12",
            src_hostname="ADMIN-LAPTOP",
            src_geo_country="US",
            dst_endpoint="MGMT-SRV-01",
            mfa_used=True,
            status="success",
            message="Interactive admin logon via Kerberos"
        ),
        FileActivityEvent(
            event_id="FILE-001",
            file_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            file_name="powershell.exe",
            action="execute",
            actor_pid=4102,
            actor_process_name="powershell.exe",
            actor_command_line="powershell.exe Get-Service -Name wuauserv",
            actor_user=user_id,
            message="Admin executed Windows Update status check"
        )
    ]

    return finding, events, store


def generate_apt_attack_chain() -> Tuple[FindingEvent, List[OCSFEvent], EntityBaselineStore]:
    """Generates a multi-stage advanced threat: Credential Stuffing -> LSASS Dump -> C2 Beacon -> Lateral Pivot."""
    store = EntityBaselineStore()
    user_id = "finance_bob"
    store.register_user_baseline(UserBaseline(
        user_id=user_id,
        allowed_subnets=["10.20.0.0/16"],
        allowed_countries=["US"],
        mfa_enforced=True
    ))

    finding = FindingEvent(
        event_id="FIND-902",
        finding_id="ALERT-CRITICAL-MIMIKATZ-01",
        rule_name="OS Credential Dumping Detected via LSASS Access",
        mitre_technique_id="T1003.001",
        description="Known credential harvesting utility accessed Local Security Authority Subsystem Service (LSASS).",
        confidence_score=0.95,
        entity_id=user_id,
        entity_type="user"
    )

    events: List[OCSFEvent] = [
        # Stage 1: Compromised login from external untrusted country without MFA
        AuthenticationEvent(
            event_id="AUTH-901",
            principal=user_id,
            src_ip="185.220.101.5",
            src_hostname="UNKNOWN-TOR-EXIT",
            src_geo_country="RO",
            dst_endpoint="WKSTN-FIN-04",
            mfa_used=False,
            status="success",
            message="Logon from high-risk external ASN without MFA challenge"
        ),
        # Stage 2: Malicious PowerShell download cradle
        FileActivityEvent(
            event_id="FILE-902",
            file_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            file_name="powershell.exe",
            action="execute",
            actor_pid=5844,
            actor_process_name="powershell.exe",
            actor_command_line="powershell.exe -enc IABlAHgA... Invoke-Mimikatz sekurlsa::logonpasswords",
            actor_user=user_id,
            message="Obfuscated PowerShell invocation targeting LSASS memory"
        ),
        # Stage 3: Dropped staging binary
        FileActivityEvent(
            event_id="FILE-903",
            file_path="C:\\Users\\bob\\AppData\\Local\\Temp\\mimikatz.exe",
            file_name="mimikatz.exe",
            action="create",
            actor_pid=5844,
            actor_process_name="powershell.exe",
            actor_command_line="mimikatz.exe",
            actor_user=user_id,
            message="Credential dumping binary created on disk"
        ),
        # Stage 4: Outbound C2 Beaconing
        NetworkActivityEvent(
            event_id="NET-904",
            src_ip="10.20.1.45",
            dst_ip="198.51.100.23",
            protocol="TCP",
            src_port=49211,
            dst_port=8443,
            bytes_sent=14520,
            bytes_received=2300,
            connection_state="ESTABLISHED",
            dns_query="c2.apt-syndicate.org",
            direction="outbound",
            message="Outbound TLS beacon to untrusted command & control IP"
        ),
        # Stage 5: Lateral Movement to Domain Controller
        AuthenticationEvent(
            event_id="AUTH-905",
            principal=user_id,
            src_ip="10.20.1.45",
            src_hostname="WKSTN-FIN-04",
            src_geo_country="US",
            dst_endpoint="DC-PROD-01",
            auth_protocol="Kerberos",
            logon_type="Network",
            mfa_used=False,
            status="success",
            message="Pivoted authentication to Tier-0 Domain Controller"
        )
    ]

    return finding, events, store

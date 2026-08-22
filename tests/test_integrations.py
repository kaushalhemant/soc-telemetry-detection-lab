import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.pcap_analyzer import PcapAnalyzer
from engine.burp_integrator import BurpIntegrator
from web.server import export_wireshark_pcap, export_burp_repeater_request, ingest_burp_proxy_xml, BurpIngestRequest, trigger_simulation, SimulationRequest
from generator.models import ScenarioType

def test_pcap_generation():
    alert_dict = {
        "alert_id": "ALT-TEST-101",
        "rule_id": "RULE-006",
        "rule_name": "Data Exfiltration via DNS TXT",
        "hostname": "host-test-alpha",
        "details": {"source_ip": "192.168.1.100"}
    }
    pcap_bytes = PcapAnalyzer.generate_pcap_bytes(alert_dict)
    assert isinstance(pcap_bytes, bytes)
    assert len(pcap_bytes) > 24
    # Check PCAP Magic Number 0xa1b2c3d4 in little-endian (b"\xd4\xc3\xb2\xa1")
    assert pcap_bytes[:4] == b"\xd4\xc3\xb2\xa1"

def test_wireshark_filter_conversion():
    rule_dict = {"id": "RULE-006", "log_source": {"log_type": "auditd.log"}}
    filter_str = PcapAnalyzer.to_wireshark_filter(rule_dict)
    assert "dns" in filter_str

def test_burp_repeater_export():
    alert_dict = {
        "alert_id": "ALT-TEST-102",
        "rule_id": "RULE-003",
        "rule_name": "Webshell Spawn",
        "hostname": "web-target",
        "sample_raw_logs": ["POST /upload.php"]
    }
    repeater_data = BurpIntegrator.export_burp_repeater(alert_dict)
    assert "POST" in repeater_data["raw_http_request"]
    assert "curl" in repeater_data["curl_command"]

def test_burp_xml_parsing():
    sample_burp_xml = """<?xml version="1.0"?>
    <items>
      <item>
        <time>Mon Jan 15 12:00:00 EST 2026</time>
        <url>http://10.0.0.1/admin/login.php</url>
        <host>10.0.0.1</host>
        <port>80</port>
        <protocol>http</protocol>
        <method>POST</method>
        <path>/admin/login.php</path>
        <status>200</status>
        <request base64="true">UE9TVCAvYWRtaW4vbG9naW4ucGhwIEhUVFAvMS4xDQpIb3N0OiAxMC4wLjAuMQ0KDQphZG1pbjFwYXNz</request>
      </item>
    </items>
    """
    events = BurpIntegrator.parse_burp_xml_logs(sample_burp_xml)
    assert len(events) == 1
    assert events[0].hostname == "10.0.0.1"
    assert events[0].details["http_method"] == "POST"

def test_integration_api_endpoints():
    # 1. Trigger simulation to ensure an alert exists
    trigger_simulation(SimulationRequest(scenario=ScenarioType.DATA_EXFILTRATION))
    
    from web.server import detection_engine
    alerts = detection_engine.alert_manager.get_all_alerts(10)
    assert len(alerts) > 0
    target_alert_id = alerts[0].alert_id

    # 2. Test Wireshark PCAP Endpoint
    response = export_wireshark_pcap(target_alert_id)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/vnd.tcpdump.pcap"

    # 3. Test Burp Repeater Export Endpoint
    burp_exp = export_burp_repeater_request(target_alert_id)
    assert "raw_http_request" in burp_exp
    assert "curl_command" in burp_exp

    # 4. Test Burp Ingest Endpoint
    burp_req = BurpIngestRequest(xml_content="""<items><item><url>http://prod-app/login</url><host>prod-app</host><method>POST</method><status>200</status></item></items>""")
    ingest_res = ingest_burp_proxy_xml(burp_req)
    assert ingest_res["status"] == "success"
    assert ingest_res["ingested_count"] == 1

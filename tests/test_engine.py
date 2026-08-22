import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from generator.models import ScenarioType, TriageStatus
from generator.log_generator import TelemetryGenerator
from engine.detection_engine import DetectionEngine
from engine.exporter import SigmaExporter

@pytest.fixture
def engine():
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
    return DetectionEngine(rules_dir=rules_dir)

def test_rules_loading(engine):
    assert len(engine.rules) >= 11, "Should load at least 11 SIGMA rules"

def test_brute_force_detection(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.BRUTE_FORCE, num_failures=8, include_success=True)

    brute_force_alerts = [a for a in alerts if a.rule_id == "RULE-001"]
    assert len(brute_force_alerts) >= 1, "Should trigger RULE-001 SSH Brute Force"
    alert = brute_force_alerts[0]
    assert alert.severity == "HIGH"
    assert alert.mitre_technique_id == "T1110.001"

def test_privilege_escalation_detection(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.PRIVILEGE_ESCALATION)

    priv_alerts = [a for a in alerts if a.rule_id == "RULE-002"]
    assert len(priv_alerts) >= 1, "Should trigger RULE-002 Privilege Escalation"
    alert = priv_alerts[0]
    assert alert.severity == "CRITICAL"
    assert alert.mitre_technique_id == "T1548.001"

def test_anomalous_process_detection(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.ANOMALOUS_PROCESS)

    proc_alerts = [a for a in alerts if a.rule_id == "RULE-003"]
    assert len(proc_alerts) >= 1, "Should trigger RULE-003 Anomalous Shell Spawn"
    alert = proc_alerts[0]
    assert alert.severity == "CRITICAL"
    assert alert.mitre_technique_id == "T1059.004"

def test_persistence_crontab_detection(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.PERSISTENCE)

    cron_alerts = [a for a in alerts if a.rule_id == "RULE-004"]
    assert len(cron_alerts) >= 1, "Should trigger RULE-004 Persistence Crontab Edit"
    alert = cron_alerts[0]
    assert alert.severity == "MEDIUM"

def test_lateral_movement_detection(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.LATERAL_MOVEMENT)

    lat_alerts = [a for a in alerts if a.rule_id == "RULE-005"]
    assert len(lat_alerts) >= 1, "Should trigger RULE-005 Lateral Movement"
    alert = lat_alerts[0]
    assert alert.severity == "HIGH"
    assert alert.mitre_technique_id == "T1021.006"

def test_data_exfiltration_detection(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.DATA_EXFILTRATION)

    exfil_alerts = [a for a in alerts if a.rule_id == "RULE-006"]
    assert len(exfil_alerts) >= 1, "Should trigger RULE-006 DNS Exfiltration"
    alert = exfil_alerts[0]
    assert alert.severity == "CRITICAL"
    assert alert.mitre_technique_id == "T1071.004"

def test_defense_evasion_detection(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.DEFENSE_EVASION)

    evasion_alerts = [a for a in alerts if a.rule_id == "RULE-007"]
    assert len(evasion_alerts) >= 1, "Should trigger RULE-007 Log Clearing Defense Evasion"
    alert = evasion_alerts[0]
    assert alert.severity == "CRITICAL"

def test_uncommon_process_hollowing_detection(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.PROCESS_HOLLOWING)

    target_alerts = [a for a in alerts if a.rule_id == "RULE-008"]
    assert len(target_alerts) >= 1, "Should trigger RULE-008 Process Hollowing"
    assert target_alerts[0].severity == "CRITICAL"
    assert target_alerts[0].mitre_technique_id == "T1055.012"

def test_uncommon_kernel_driver_tampering_detection(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.KERNEL_DRIVER_TAMPERING)

    target_alerts = [a for a in alerts if a.rule_id == "RULE-009"]
    assert len(target_alerts) >= 1, "Should trigger RULE-009 Kernel Driver Tampering"
    assert target_alerts[0].severity == "CRITICAL"
    assert target_alerts[0].mitre_technique_id == "T1068"

def test_uncommon_kerberoasting_detection(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.KERBEROASTING)

    target_alerts = [a for a in alerts if a.rule_id == "RULE-010"]
    assert len(target_alerts) >= 1, "Should trigger RULE-010 Kerberoasting TGS Request"
    assert target_alerts[0].severity == "HIGH"
    assert target_alerts[0].mitre_technique_id == "T1558.003"

def test_uncommon_lsass_dump_detection(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.LSASS_DUMP)

    target_alerts = [a for a in alerts if a.rule_id == "RULE-011"]
    assert len(target_alerts) >= 1, "Should trigger RULE-011 LSASS Memory Dump"
    assert target_alerts[0].severity == "CRITICAL"
    assert target_alerts[0].mitre_technique_id == "T1003.001"

def test_baseline_traffic_no_false_positives(engine):
    alerts = []
    engine.register_alert_listener(lambda a: alerts.append(a))
    
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.NORMAL_BASELINE, count=20)
    assert len(alerts) == 0, "Normal baseline traffic should produce zero false positive alerts"

def test_metrics_and_exporter(engine):
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.ANOMALOUS_PROCESS)

    summary = engine.metrics_engine.get_summary()
    assert summary["total_events_processed"] > 0
    assert summary["precision_pct"] >= 0.0

    rule = engine.rules[0]
    splunk_spl = SigmaExporter.to_splunk(rule)
    elastic_kql = SigmaExporter.to_elastic(rule)
    assert "index=" in splunk_spl or "log_type=" in splunk_spl
    assert ":" in elastic_kql

    nav = SigmaExporter.generate_mitre_navigator_layer(engine.rules)
    assert nav["domain"] == "enterprise-attack"
    assert len(nav["techniques"]) > 0

def test_alert_triage_workflow(engine):
    gen = TelemetryGenerator()
    gen.register_listener(engine.process_event)
    gen.trigger_scenario(ScenarioType.ANOMALOUS_PROCESS)

    alerts = engine.alert_manager.get_all_alerts()
    assert len(alerts) > 0
    target_alert = alerts[0]

    updated = engine.alert_manager.update_triage_status(target_alert.alert_id, TriageStatus.INVESTIGATING, "Initiated forensic memory dump")
    assert updated.status == TriageStatus.INVESTIGATING
    assert len(updated.analyst_notes) == 1

    tuned = engine.alert_manager.tune_alert_rule(target_alert.alert_id, new_threshold=10)
    assert tuned.tuned is True

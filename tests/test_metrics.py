import os
import sys
import pytest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from generator.models import LogEvent, LogType, DetectionAlert, SeverityLevel, TriageStatus
from engine.metrics import MetricsEngine, calculate_latency_ms, parse_iso_timestamp
from engine.detection_validator import DetectionValidator
from web.server import run_detection_validation, app


def make_test_event(
    event_id: str = "TEST_EVENT",
    ground_truth: str = None,
    telemetry_source: str = "simulated",
    timestamp: str = None
) -> LogEvent:
    now_str = timestamp or datetime.now(timezone.utc).isoformat()
    return LogEvent(
        id="evt-test-01",
        timestamp=now_str,
        log_type=LogType.AUDITD,
        hostname="test-host",
        event_id=event_id,
        raw_message=f"Test log message for {event_id}",
        details={},
        telemetry_source=telemetry_source,
        ground_truth=ground_truth
    )


def make_test_alert(
    rule_id: str = "RULE-001",
    timestamp: str = None,
    ground_truth_label: str = None,
    telemetry_source: str = "simulated"
) -> DetectionAlert:
    now_str = timestamp or datetime.now(timezone.utc).isoformat()
    return DetectionAlert(
        alert_id="ALT-TEST-999",
        rule_id=rule_id,
        rule_name="Test Rule",
        severity=SeverityLevel.HIGH,
        timestamp=now_str,
        mitre_tactic="Initial Access",
        mitre_technique_id="T1110",
        mitre_technique_name="Brute Force",
        hostname="test-host",
        description="Test alert description",
        triggering_event_ids=["evt-test-01"],
        sample_raw_logs=["raw log sample"],
        remediation_suggestion="Isolate host",
        status=TriageStatus.NEW,
        telemetry_source=telemetry_source,
        ground_truth_label=ground_truth_label
    )


def test_zero_events_metrics():
    """When no events or detections have been processed, all performance metrics must be None."""
    engine = MetricsEngine()
    summary = engine.get_summary()

    assert summary["total_events_processed"] == 0
    assert summary["true_positives"] == 0
    assert summary["false_positives"] == 0
    assert summary["false_negatives"] == 0
    assert summary["true_negatives"] == 0

    assert summary["precision_pct"] is None, "Precision must be None when TP + FP == 0"
    assert summary["recall_pct"] is None, "Recall must be None when TP + FN == 0"
    assert summary["false_positive_rate_pct"] is None, "FPR must be None when FP + TN == 0"
    assert summary["mttd_ms"] is None, "MTTD must be None when no detections recorded"
    assert summary["has_validated_data"] is False


def test_missing_ground_truth():
    """Unlabeled telemetry must not artificially inflate TP, FP, or TN."""
    engine = MetricsEngine()
    unlabeled_evt = make_test_event(
        event_id="CUSTOM_APP_DIAGNOSTIC",
        ground_truth=None,
        telemetry_source="live"
    )
    engine.record_event(unlabeled_evt)

    summary1 = engine.get_summary()
    assert summary1["total_events_processed"] == 1
    assert summary1["live_events"] == 1
    assert summary1["unlabeled_events"] == 1
    assert summary1["true_negatives"] == 0
    assert summary1["precision_pct"] is None
    assert summary1["recall_pct"] is None
    assert summary1["false_positive_rate_pct"] is None

    # Record alert without ground truth validation
    unlabeled_alert = make_test_alert(ground_truth_label=None, telemetry_source="live")
    engine.record_detection(unlabeled_alert, primary_event=unlabeled_evt)

    summary2 = engine.get_summary()
    assert summary2["true_positives"] == 0, "Unlabeled detection must not be counted as TP"
    assert summary2["false_positives"] == 0, "Unlabeled detection must not be counted as FP"
    assert summary2["unlabeled_detections"] == 1
    assert summary2["precision_pct"] is None, "Precision must remain None without validated observations"


def test_zero_denominators():
    """Validates that each metric formula correctly handles zero denominators independently."""
    # Case A: Only TN observed (benign event, no alerts)
    engine_a = MetricsEngine()
    benign_evt = make_test_event(ground_truth="benign")
    engine_a.record_event(benign_evt)

    sum_a = engine_a.get_summary()
    assert sum_a["true_negatives"] == 1
    assert sum_a["precision_pct"] is None, "Precision denominator (TP+FP=0) must yield None"
    assert sum_a["recall_pct"] is None, "Recall denominator (TP+FN=0) must yield None"
    assert sum_a["false_positive_rate_pct"] == 0.0, "FPR with FP=0 and TN=1 must be 0.0%"

    # Case B: Only TP observed (attack event with detection)
    engine_b = MetricsEngine()
    attack_evt = make_test_event(ground_truth="attack")
    engine_b.record_event(attack_evt)
    alert_b = make_test_alert(ground_truth_label="attack")
    engine_b.record_detection(alert_b, primary_event=attack_evt)

    sum_b = engine_b.get_summary()
    assert sum_b["true_positives"] == 1
    assert sum_b["precision_pct"] == 100.0, "Precision with TP=1 and FP=0 must be 100.0%"
    assert sum_b["recall_pct"] == 100.0, "Recall with TP=1 and FN=0 must be 100.0%"
    assert sum_b["false_positive_rate_pct"] is None, "FPR denominator (FP+TN=0) must yield None"

    # Case C: Only FN observed (missed attack)
    engine_c = MetricsEngine()
    engine_c.record_missed_attack()
    sum_c = engine_c.get_summary()
    assert sum_c["false_negatives"] == 1
    assert sum_c["precision_pct"] is None, "Precision denominator must be None"
    assert sum_c["recall_pct"] == 0.0, "Recall with TP=0 and FN=1 must be 0.0%"


def test_malformed_and_missing_timestamps():
    """MTTD calculation must reject malformed, missing, and non-chronological timestamps."""
    # Test timestamp parser directly
    assert parse_iso_timestamp(None) is None
    assert parse_iso_timestamp("") is None
    assert parse_iso_timestamp("not-a-timestamp") is None
    assert parse_iso_timestamp("2026-99-99T99:99:99Z") is None

    # Test calculate_latency_ms
    assert calculate_latency_ms(None, "2026-08-17T12:00:00Z") is None
    assert calculate_latency_ms("2026-08-17T12:00:00Z", None) is None
    assert calculate_latency_ms("bad-ts-1", "bad-ts-2") is None

    # Non-chronological (detection happened before event)
    t_event = "2026-08-17T12:05:00Z"
    t_alert_earlier = "2026-08-17T12:04:00Z"
    assert calculate_latency_ms(t_event, t_alert_earlier) is None, "Negative latency must be rejected"

    # Excessive delta (beyond real-time correlation window, e.g. replaying months-old logs)
    t_alert_hours_later = "2026-08-17T13:00:00Z"
    assert calculate_latency_ms(t_event, t_alert_hours_later) is None, "Excessive latency must be rejected"

    # Valid chronological pair (350 ms latency)
    t_evt = "2026-08-17T12:00:00.000Z"
    t_alt = "2026-08-17T12:00:00.350Z"
    latency = calculate_latency_ms(t_evt, t_alt)
    assert latency == 350.0

    # Ensure engine does not record fake default latency
    engine = MetricsEngine()
    bad_evt = make_test_event(timestamp="invalid-timestamp", ground_truth="attack")
    bad_alt = make_test_alert(timestamp="another-invalid", ground_truth_label="attack")
    engine.record_detection(bad_alt, primary_event=bad_evt)
    assert engine.get_summary()["mttd_ms"] is None, "MTTD must be None when timestamps are invalid"


def test_valid_known_examples():
    """Validates exact math against known benchmark confusion matrix."""
    engine = MetricsEngine()

    # Ingest 8 True Positives
    for i in range(8):
        evt = make_test_event(ground_truth="attack", timestamp=f"2026-08-17T12:00:{i:02d}.000Z")
        alt = make_test_alert(ground_truth_label="attack", timestamp=f"2026-08-17T12:00:{i:02d}.200Z")
        engine.record_event(evt)
        engine.record_detection(alt, primary_event=evt, latency_ms=200.0)

    # Ingest 2 False Positives (detections triggered on benign baseline)
    for i in range(2):
        evt = make_test_event(ground_truth="benign", timestamp="2026-08-17T12:01:00.000Z")
        alt = make_test_alert(ground_truth_label="benign", timestamp="2026-08-17T12:01:00.100Z")
        engine.record_event(evt)
        engine.record_detection(alt, primary_event=evt, latency_ms=100.0)

    # Ingest 2 False Negatives (missed attacks)
    engine.record_missed_attack()
    engine.record_missed_attack()

    # Ingest 8 True Negatives (benign events with no alert)
    for _ in range(8):
        evt = make_test_event(ground_truth="benign")
        engine.record_event(evt)

    summary = engine.get_summary()

    # Precision = TP / (TP + FP) = 8 / (8 + 2) = 80.0%
    assert summary["true_positives"] == 8
    assert summary["false_positives"] == 2
    assert summary["precision_pct"] == 80.0
    assert summary["precision_denominator"] == 10

    # Recall = TP / (TP + FN) = 8 / (8 + 2) = 80.0%
    assert summary["false_negatives"] == 2
    assert summary["recall_pct"] == 80.0
    assert summary["recall_denominator"] == 10

    # FPR = FP / (FP + TN) = 2 / (2 + 8) = 20.0%
    assert summary["true_negatives"] == 8
    assert summary["false_positive_rate_pct"] == 20.0
    assert summary["fpr_denominator"] == 10

    # MTTD = (8 * 200 + 2 * 100) / 10 = 1800 / 10 = 180.0 ms
    assert summary["mttd_ms"] == 180.0
    assert summary["mttd_sample_count"] == 10


def test_deterministic_detection_validator():
    """Validates that the deterministic detection validation test suite executes successfully."""
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")
    validator = DetectionValidator(rules_dir=rules_dir)
    res = validator.run_validation_suite()

    assert res["total_scenarios"] == 13
    assert res["passed_scenarios"] == 13
    assert res["failed_scenarios"] == 0
    assert res["pass_rate_pct"] == 100.0
    assert res["metrics"]["precision_pct"] == 100.0
    assert res["metrics"]["recall_pct"] == 100.0
    assert res["metrics"]["false_positive_rate_pct"] == 0.0
    assert "disclaimer" in res


def test_detection_test_api_endpoint():
    """Validates the /api/detection-tests/run REST API endpoint."""
    res = run_detection_validation()
    assert "total_scenarios" in res
    assert res["total_scenarios"] >= 13
    assert "confusion_matrix" in res
    assert "metrics" in res
    assert "scenarios" in res

import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web.server import (
    run_demonstration_workflow,
    reset_demonstration_session,
    export_demonstration_report,
    detection_engine
)
from generator.attack_simulators import generate_demonstration_dataset
from engine.metrics import MetricsEngine
from generator.models import LogEvent, LogType


def test_master_demo_workflow():
    """Validates the 1-click master demonstration workflow execution and metric generation."""
    res = run_demonstration_workflow()

    assert res["status"] == "success"
    assert res["events_processed"] >= 35, "Master demo should process 35+ events"
    assert res["alerts_generated"] >= 5, "Master demo should trigger multiple detections"

    cm = res["confusion_matrix"]
    assert cm["true_positives"] >= 5, "True positives must be >= 5"
    assert cm["true_negatives"] >= 15, "True negatives from benign baseline must be >= 15"
    assert cm["false_negatives"] >= 1, "Stealth evasion must be documented as at least 1 False Negative"

    m = res["metrics"]
    assert m["precision_pct"] is not None and m["precision_pct"] > 0.0
    assert m["recall_pct"] is not None and m["recall_pct"] > 0.0
    assert m["false_positive_rate_pct"] is not None
    assert m["mttd_ms"] is not None and m["mttd_ms"] >= 0.0

    assert len(res["scenarios_evaluated"]) == 8


def test_demo_reset_workflow():
    """Validates that demo session reset returns metrics and alert queues to clean states."""
    # Ensure some detections exist
    run_demonstration_workflow()
    assert len(detection_engine.alert_manager.alert_history) > 0

    # Reset
    reset_res = reset_demonstration_session()
    assert reset_res["status"] == "success"
    assert len(detection_engine.alert_manager.alert_history) == 0

    metrics = reset_res["metrics"]
    assert metrics["total_events_processed"] == 0
    assert metrics["precision_pct"] is None
    assert metrics["recall_pct"] is None
    assert metrics["has_validated_data"] is False


def test_demo_reports():
    """Validates Markdown, HTML, and JSON report generation endpoints."""
    # Run demo first to populate report data
    run_demonstration_workflow()

    # Markdown format
    md_resp = export_demonstration_report(format="markdown")
    assert "SOC Telemetry Detection Lab" in md_resp.body.decode("utf-8")
    assert "Confusion Matrix Breakdown" in md_resp.body.decode("utf-8")

    # HTML format
    html_resp = export_demonstration_report(format="html")
    assert "<!DOCTYPE html>" in html_resp.body.decode("utf-8")
    assert "SOC Telemetry Detection Lab" in html_resp.body.decode("utf-8")

    # JSON format
    json_resp = export_demonstration_report(format="json")
    assert json_resp["report_type"] == "SOC_DEMONSTRATION_AUDIT"
    assert "metrics" in json_resp
    assert "alerts" in json_resp


def test_event_deduplication_and_ground_truth():
    """Validates that repeated event IDs are deduplicated and ground truth labels are preserved."""
    engine = MetricsEngine()

    evt1 = LogEvent(
        id="unique-evt-001",
        timestamp="2026-08-17T12:00:00.000Z",
        log_type=LogType.AUTH,
        hostname="test-host",
        event_id="SSH_AUTH_FAIL",
        raw_message="auth fail",
        ground_truth="malicious"
    )

    # Ingest twice
    engine.record_event(evt1)
    engine.record_event(evt1)

    summary = engine.get_summary()
    assert summary["total_events_processed"] == 1, "Duplicate event ID must be counted only once"
    assert summary["total_malicious_events"] == 1

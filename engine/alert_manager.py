import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from generator.models import LogEvent, DetectionAlert, TriageStatus
from .rule_parser import Rule

class AlertManager:
    """
    Manages generation, formatting, history tracking, and triage workflow of SOC Security Detections.
    """
    def __init__(self):
        self.alert_history: List[DetectionAlert] = []

    def create_alert(
        self,
        rule: Rule,
        triggering_events: List[LogEvent],
        group_key: str = None
    ) -> DetectionAlert:
        """
        Creates a standardized DetectionAlert object from a matched rule and set of triggering log events.
        """
        primary_event = triggering_events[-1]
        raw_logs = [evt.raw_message for evt in triggering_events]
        event_ids = [evt.id for evt in triggering_events]

        remediation_text = "\n".join([f"• {r}" for r in rule.remediation]) if rule.remediation else "• Investigate user and isolate affected host."

        desc = rule.description
        if group_key and rule.threshold_group_by:
            desc += f" (Threshold breached: {len(triggering_events)} events for {rule.threshold_group_by}={group_key})"

        # Extract matched fields and build triggering condition rationale
        matched_fields = {}
        for k, expected_v in rule.selection.items():
            actual_v = getattr(primary_event, k, None)
            if actual_v is None and hasattr(primary_event, "details"):
                actual_v = primary_event.details.get(k)
            matched_fields[k] = {"expected": expected_v, "actual": actual_v}

        explanation_parts = [f"{k}='{v['actual']}'" for k, v in matched_fields.items() if v["actual"] is not None]
        explanation = f"Rule condition matched on {rule.log_type}: " + ", ".join(explanation_parts)
        if group_key and rule.threshold_group_by:
            explanation += f" (Threshold breached: {len(triggering_events)}/{rule.threshold_count} events on {rule.threshold_group_by}='{group_key}')"

        gt_label = getattr(primary_event, "ground_truth", None) or primary_event.details.get("ground_truth")

        alert = DetectionAlert(
            alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            rule_id=rule.id,
            rule_name=rule.title,
            severity=rule.severity,
            timestamp=datetime.now(timezone.utc).isoformat(),
            mitre_tactic=rule.mitre_tactic,
            mitre_technique_id=rule.mitre_technique_id,
            mitre_technique_name=rule.mitre_technique_name,
            hostname=primary_event.hostname,
            container_id=primary_event.container_id,
            description=desc,
            triggering_event_ids=event_ids,
            sample_raw_logs=raw_logs[:5],
            remediation_suggestion=remediation_text,
            details={
                "source_ip": primary_event.source_ip,
                "user": primary_event.user,
                "process_name": primary_event.process_name,
                "event_id": primary_event.event_id,
                "event_count": len(triggering_events),
                "matched_fields": matched_fields,
                "trigger_reason": explanation,
                "confidence_assessment": f"Signature match against {rule.id} ({rule.title}). Indicates activity consistent with {rule.mitre_tactic} ({rule.mitre_technique_id}). Does not constitute proof of confirmed compromise without corroborating host forensics.",
                "scenario_id": getattr(primary_event, "scenario_id", None),
                "primary_event_details": getattr(primary_event, "details", {})
            },
            status=TriageStatus.NEW,
            analyst_notes=[],
            tuned=False,
            telemetry_source=getattr(primary_event, "telemetry_source", "simulated"),
            ground_truth_label=gt_label,
            classification="TP" if gt_label in ["malicious", "attack"] else ("FP" if gt_label == "benign" else None)
        )

        self.alert_history.insert(0, alert)  # Keep latest at top
        return alert

    def get_alert_by_id(self, alert_id: str) -> Optional[DetectionAlert]:
        for alt in self.alert_history:
            if alt.alert_id == alert_id:
                return alt
        return None

    def update_triage_status(self, alert_id: str, status: TriageStatus, note: Optional[str] = None) -> Optional[DetectionAlert]:
        alert = self.get_alert_by_id(alert_id)
        if alert:
            alert.status = status
            if note:
                timestamp_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
                alert.analyst_notes.append(f"[{timestamp_str}] [{status.value}] {note}")
        return alert

    def add_analyst_note(self, alert_id: str, note: str) -> Optional[DetectionAlert]:
        alert = self.get_alert_by_id(alert_id)
        if alert:
            timestamp_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
            alert.analyst_notes.append(f"[{timestamp_str}] {note}")
        return alert

    def tune_alert_rule(self, alert_id: str, new_threshold: int = 10) -> Optional[DetectionAlert]:
        alert = self.get_alert_by_id(alert_id)
        if alert:
            alert.tuned = True
            timestamp_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
            alert.analyst_notes.append(f"[{timestamp_str}] [RULE_TUNED] Threshold raised to {new_threshold} for rule {alert.rule_id} to suppress false positives.")
        return alert

    def get_all_alerts(self, limit: int = 50) -> List[DetectionAlert]:
        return self.alert_history[:limit]

    def clear_alerts(self):
        self.alert_history.clear()

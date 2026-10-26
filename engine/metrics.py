import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from generator.models import LogEvent, DetectionAlert


def parse_iso_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Safely parses an ISO 8601 / RFC 3339 timestamp string into a UTC datetime object."""
    if not ts_str or not isinstance(ts_str, str):
        return None
    try:
        val = ts_str.strip()
        if val.endswith("Z"):
            val = val[:-1] + "+00:00"
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def calculate_latency_ms(
    event_timestamp: Optional[str],
    detection_timestamp: Optional[str]
) -> Optional[float]:
    """
    Calculates detection latency in milliseconds between the triggering event
    and the detection alert timestamp.
    Returns None if timestamps are missing, malformed, or chronologically invalid.
    """
    event_dt = parse_iso_timestamp(event_timestamp)
    alert_dt = parse_iso_timestamp(detection_timestamp)

    if not event_dt or not alert_dt:
        return None

    delta_seconds = (alert_dt - event_dt).total_seconds()
    # Detection must occur at or after event time; allow up to 10 minutes window for real-time detection
    if 0.0 <= delta_seconds <= 600.0:
        return round(delta_seconds * 1000.0, 2)
    return None


class MetricsEngine:
    """
    Calculates SOC Detection Engineering Efficacy Metrics:
    - Precision = TP / (TP + FP)
    - Recall = TP / (TP + FN)
    - False Positive Rate (FPR) = FP / (FP + TN)
    - Mean Time to Detect (MTTD in milliseconds)

    Guarantees:
    - Never displays 100% precision or recall when there are no validated observations.
    - Returns None (rendered as 'N/A — insufficient data' in UI) when denominators are zero.
    - Only calculates performance metrics when ground-truth labels exist.
    - Only calculates MTTD when valid event and detection timestamps exist.
    - Tracks sample sizes, measurement scope, and separates simulated vs live telemetry.
    """

    KNOWN_BENIGN_EVENT_IDS = {
        "WEB_NORMAL_ACCESS",
        "SSH_AUTH_SUCCESS",
        "BASELINE_SYSCALL",
        "CLIENT_HEARTBEAT",
        "CLIENT_IDLE_HEARTBEAT",
        "CLIENT_DEVICE_DISCOVERED",
        "CLIENT_DEVICE_HEARTBEAT"
    }

    KNOWN_ATTACK_EVENT_IDS = {
        "SSH_AUTH_FAIL",
        "AUDITD_EXECVE_SUID",
        "SUDO_PRIV_ELEVATION",
        "AUDITD_ROOT_SHELL_SPAWN",
        "WEB_SUSPICIOUS_PAYLOAD",
        "AUDITD_ANOMALOUS_CHILD_PROCESS",
        "PERSISTENCE_CRON_EDIT",
        "LATERAL_WINRM_EXEC",
        "EXFIL_DNS_TUNNEL",
        "EVASION_LOG_CLEAR",
        "AUDITD_EXECVE",
        "KERNEL_DRIVER_LOAD",
        "KERBEROS_TGS_REQUEST",
        "SUID_EXEC",
        "WEBSHELL_SPAWN",
        "CRON_PERSISTENCE",
        "LATERAL_WINRM",
        "DNS_EXFIL",
        "LOG_CLEARING",
        "PROCESS_HOLLOWING",
        "KERNEL_DRIVER_TAMPERING",
        "KERBEROASTING_TGS",
        "LSASS_DUMP"
    }

    def __init__(self):
        self.total_events_processed: int = 0
        self.simulated_events_count: int = 0
        self.live_events_count: int = 0
        self.replayed_events_count: int = 0
        self.unlabeled_events_count: int = 0

        self.total_attack_events: int = 0
        self.total_baseline_events: int = 0

        self.true_positives: int = 0
        self.false_positives: int = 0
        self.false_negatives: int = 0
        self.true_negatives: int = 0
        self.unlabeled_detections: int = 0

        self.detection_latencies_ms: List[float] = []

    def _resolve_ground_truth(self, event: LogEvent) -> Optional[str]:
        """Resolves whether an event is validated as 'attack', 'benign', or unlabeled (None)."""
        gt = getattr(event, "ground_truth", None) or event.details.get("ground_truth")
        if gt in ["attack", "benign"]:
            return gt

        # If simulated without explicit field, infer from known event IDs
        source = getattr(event, "telemetry_source", "simulated")
        if source == "simulated":
            if event.event_id in self.KNOWN_BENIGN_EVENT_IDS:
                return "benign"
            if event.event_id in self.KNOWN_ATTACK_EVENT_IDS:
                return "attack"

        # Live and unknown telemetry defaults to unlabeled (no assumed ground truth)
        return None

    def record_event(self, event: LogEvent):
        """Records an ingested event and categorizes ground truth if available."""
        self.total_events_processed += 1

        source = getattr(event, "telemetry_source", "simulated")
        if source == "live":
            self.live_events_count += 1
        elif source == "replayed":
            self.replayed_events_count += 1
        else:
            self.simulated_events_count += 1

        ground_truth = self._resolve_ground_truth(event)
        if ground_truth == "attack":
            self.total_attack_events += 1
        elif ground_truth == "benign":
            self.total_baseline_events += 1
            self.true_negatives += 1
        else:
            self.unlabeled_events_count += 1

    def record_detection(
        self,
        alert: DetectionAlert,
        primary_event: Optional[LogEvent] = None,
        latency_ms: Optional[float] = None
    ):
        """
        Records a detection alert. Evaluates TP vs FP only when ground truth is verified.
        Computes latency from valid timestamps if not explicitly provided.
        """
        # Determine ground truth from primary triggering event or alert metadata
        ground_truth = None
        if primary_event:
            ground_truth = self._resolve_ground_truth(primary_event)
        if not ground_truth:
            gt_label = getattr(alert, "ground_truth_label", None) or alert.details.get("ground_truth")
            if gt_label in ["attack", "benign"]:
                ground_truth = gt_label
            else:
                event_id = alert.details.get("event_id")
                if event_id in self.KNOWN_BENIGN_EVENT_IDS:
                    ground_truth = "benign"
                elif event_id in self.KNOWN_ATTACK_EVENT_IDS:
                    ground_truth = "attack"

        # Evaluate detection classification
        if ground_truth == "attack":
            self.true_positives += 1
            alert.ground_truth_label = "attack"
        elif ground_truth == "benign":
            self.false_positives += 1
            alert.ground_truth_label = "benign"
            if self.true_negatives > 0:
                self.true_negatives -= 1
        else:
            self.unlabeled_detections += 1
            alert.ground_truth_label = None

        # Determine detection latency
        computed_latency = latency_ms
        if computed_latency is None and primary_event and primary_event.timestamp:
            computed_latency = calculate_latency_ms(primary_event.timestamp, alert.timestamp)

        if computed_latency is not None and computed_latency >= 0.0:
            self.detection_latencies_ms.append(computed_latency)
            alert.detection_latency_ms = computed_latency

    def record_missed_attack(self):
        """Records a verified attack scenario that failed to trigger an alert (False Negative)."""
        self.false_negatives += 1

    def get_summary(self) -> Dict[str, Any]:
        """
        Calculates and returns SOC detection efficacy summary.
        Metrics return None when denominators are zero (insufficient data).
        """
        tp = self.true_positives
        fp = self.false_positives
        fn = self.false_negatives
        tn = max(0, self.true_negatives)

        # Precision = TP / (TP + FP)
        precision_denom = tp + fp
        precision = round((tp / precision_denom) * 100.0, 1) if precision_denom > 0 else None

        # Recall = TP / (TP + FN)
        recall_denom = tp + fn
        recall = round((tp / recall_denom) * 100.0, 1) if recall_denom > 0 else None

        # False Positive Rate = FP / (FP + TN)
        fpr_denom = fp + tn
        fpr = round((fp / fpr_denom) * 100.0, 2) if fpr_denom > 0 else None

        # MTTD = sum(latencies) / count
        mttd_count = len(self.detection_latencies_ms)
        mttd_ms = round(sum(self.detection_latencies_ms) / mttd_count, 2) if mttd_count > 0 else None

        return {
            "total_events_processed": self.total_events_processed,
            "simulated_events": self.simulated_events_count,
            "live_events": self.live_events_count,
            "replayed_events": self.replayed_events_count,
            "unlabeled_events": self.unlabeled_events_count,
            "total_attack_events": self.total_attack_events,
            "total_baseline_events": self.total_baseline_events,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "unlabeled_detections": self.unlabeled_detections,
            "total_alerts_generated": tp + fp + self.unlabeled_detections,
            "precision_pct": precision,
            "recall_pct": recall,
            "false_positive_rate_pct": fpr,
            "mttd_ms": mttd_ms,
            "mean_time_to_detect_ms": mttd_ms,
            "precision_denominator": precision_denom,
            "recall_denominator": recall_denom,
            "fpr_denominator": fpr_denom,
            "mttd_sample_count": mttd_count,
            "has_validated_data": (precision_denom > 0 or recall_denom > 0 or fpr_denom > 0),
            "measurement_scope": "ground_truth_validated_only"
        }

    def reset(self):
        """Resets all metrics and latencies to clean initial state."""
        self.__init__()

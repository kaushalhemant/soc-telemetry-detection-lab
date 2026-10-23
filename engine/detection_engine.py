
import time
from datetime import datetime, timezone
from collections import defaultdict
from typing import List, Callable, Dict, Optional

from generator.models import LogEvent, DetectionAlert
from .rule_parser import Rule, load_rules_from_directory
from .alert_manager import AlertManager
from .metrics import MetricsEngine


class DetectionEngine:
    """
    Real-time detection engine that checks LogEvents against loaded rules,
    maintains sliding time windows, and emits alerts.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: List[Rule] = []
        self.alert_manager = AlertManager()
        self.metrics_engine = MetricsEngine()
        self.alert_listeners: List[Callable[[DetectionAlert], None]] = []

        # Sliding window: rule ID -> group key -> (event timestamp, event)
        self.event_buffers: Dict[
            str, Dict[str, List[tuple]]
        ] = defaultdict(lambda: defaultdict(list))

        # Newest event timestamp seen for each rule/group.
        self.event_watermarks: Dict[str, float] = {}

        # Prevent repeated alerts for the same rule/group.
        self.alert_cooldowns: Dict[str, float] = {}

        self.rules_dir = rules_dir

        if rules_dir:
            self.load_rules(rules_dir)

    def load_rules(self, rules_dir: str):
        self.rules_dir = rules_dir
        self.rules = load_rules_from_directory(rules_dir)
        print(
            f"[DetectionEngine] Successfully loaded "
            f"{len(self.rules)} rules from {rules_dir}"
        )

    def reload_rules(self) -> int:
        """Reload all rules from the configured directory."""
        if self.rules_dir:
            self.load_rules(self.rules_dir)
        return len(self.rules)

    def register_alert_listener(
        self, listener: Callable[[DetectionAlert], None]
    ):
        if listener not in self.alert_listeners:
            self.alert_listeners.append(listener)

    def process_event(self, event: LogEvent) -> List[DetectionAlert]:
        """Evaluate one event and return any generated alerts."""
        self.metrics_engine.record_event(event)
        generated_alerts = []
        now_ts = time.time()

        for rule in self.rules:
            if not rule.matches_single_event(event):
                continue

            # Rules that need only one matching event.
            if rule.threshold_count <= 1:
                cooldown_key = (
                    f"{rule.id}:{event.source_ip or event.hostname}"
                )

                if (
                    now_ts - self.alert_cooldowns.get(cooldown_key, 0.0)
                    > 10.0
                ):
                    alert = self.alert_manager.create_alert(rule, [event])
                    self.alert_cooldowns[cooldown_key] = now_ts
                    self.metrics_engine.record_detection(alert)
                    generated_alerts.append(alert)
                    self._notify_listeners(alert)

                continue

            # Threshold-based rules: group events by the configured field.
            group_key = self._get_group_key(
                event, rule.threshold_group_by
            )
            watermark_key = f"{rule.id}:{group_key}"
            event_ts = self._parse_event_timestamp(event)

            # Never move the group's event-time window backwards.
            watermark = max(
                event_ts,
                self.event_watermarks.get(watermark_key, event_ts),
            )
            self.event_watermarks[watermark_key] = watermark

            window_start = watermark - rule.time_window_seconds
            buf = self.event_buffers[rule.id][group_key]

            # Discard events that are outside the active window.
            if event_ts < window_start:
                self.event_buffers[rule.id][group_key] = [
                    (ts, evt)
                    for ts, evt in buf
                    if window_start <= ts <= watermark
                ]
                continue

            buf.append((event_ts, event))

            active_buf = [
                (ts, evt)
                for ts, evt in buf
                if window_start <= ts <= watermark
            ]
            self.event_buffers[rule.id][group_key] = active_buf

            # Generate an alert after the threshold is reached.
            if len(active_buf) >= rule.threshold_count:
                cooldown_key = f"{rule.id}:{group_key}"

                if (
                    now_ts - self.alert_cooldowns.get(cooldown_key, 0.0)
                    > 20.0
                ):
                    matched_events = [evt for _, evt in active_buf]

                    alert = self.alert_manager.create_alert(
                        rule,
                        matched_events,
                        group_key=group_key,
                    )

                    self.alert_cooldowns[cooldown_key] = now_ts
                    self.metrics_engine.record_detection(alert)
                    generated_alerts.append(alert)
                    self._notify_listeners(alert)

                    # Clear the buffer after alert generation.
                    self.event_buffers[rule.id][group_key] = []

        return generated_alerts

    def _parse_event_timestamp(self, event: LogEvent) -> float:
        """Convert an event timestamp into a UTC Unix timestamp."""
        try:
            value = event.timestamp.strip()

            if value.endswith("Z"):
                value = value[:-1] + "+00:00"

            parsed = datetime.fromisoformat(value)

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed.timestamp()

        except (AttributeError, TypeError, ValueError, OverflowError):
            # Fallback for malformed or missing timestamps.
            return time.time()

    def _get_group_key(
        self, event: LogEvent, group_by_field: Optional[str]
    ) -> str:
        if not group_by_field:
            return event.hostname

        value = getattr(event, group_by_field, None)

        if value is None:
            value = event.details.get(group_by_field, "global")

        return str(value)

    def _notify_listeners(self, alert: DetectionAlert):
        for listener in self.alert_listeners:
            try:
                listener(alert)
            except Exception as exc:
                print(
                    f"[DetectionEngine Error] Alert callback error: {exc}"
                )


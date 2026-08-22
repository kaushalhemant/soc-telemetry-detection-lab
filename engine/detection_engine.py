import time
from collections import defaultdict
from typing import List, Callable, Dict, Any, Optional
from generator.models import LogEvent, DetectionAlert
from .rule_parser import Rule, load_rules_from_directory
from .alert_manager import AlertManager
from .metrics import MetricsEngine

class DetectionEngine:
    """
    Real-time Detection Engine that ingests LogEvents, checks loaded SIGMA rules,
    maintains stateful sliding window threshold buffers, and emits alerts.
    """
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: List[Rule] = []
        self.alert_manager = AlertManager()
        self.metrics_engine = MetricsEngine()
        self.alert_listeners: List[Callable[[DetectionAlert], None]] = []
        
        # Sliding time window buffer for threshold rules
        # Format: rule_id -> group_key -> list of (timestamp_float, LogEvent)
        self.event_buffers: Dict[str, Dict[str, List[tuple]]] = defaultdict(lambda: defaultdict(list))
        
        # Deduplication tracker to prevent alert storms (rule_id + group_key -> last_alert_time)
        self.alert_cooldowns: Dict[str, float] = {}

        if rules_dir:
            self.load_rules(rules_dir)

    def load_rules(self, rules_dir: str):
        self.rules = load_rules_from_directory(rules_dir)
        print(f"[DetectionEngine] Successfully loaded {len(self.rules)} rules from {rules_dir}")

    def register_alert_listener(self, listener: Callable[[DetectionAlert], None]):
        if listener not in self.alert_listeners:
            self.alert_listeners.append(listener)

    def process_event(self, event: LogEvent) -> List[DetectionAlert]:
        """
        Evaluates a single incoming LogEvent against all active rules.
        Returns any generated alerts.
        """
        self.metrics_engine.record_event(event)
        generated_alerts = []
        now_ts = time.time()

        for rule in self.rules:
            if not rule.matches_single_event(event):
                continue

            # Check if this rule is a threshold rule or single-match rule
            if rule.threshold_count <= 1:
                # Single-event match detection
                cooldown_key = f"{rule.id}:{event.source_ip or event.hostname}"
                if now_ts - self.alert_cooldowns.get(cooldown_key, 0.0) > 10.0:  # 10s cooldown
                    alert = self.alert_manager.create_alert(rule, [event])
                    self.alert_cooldowns[cooldown_key] = now_ts
                    self.metrics_engine.record_detection(alert)
                    generated_alerts.append(alert)
                    self._notify_listeners(alert)
            else:
                # Stateful sliding-window threshold match
                group_key = self._get_group_key(event, rule.threshold_group_by)
                buf = self.event_buffers[rule.id][group_key]
                buf.append((now_ts, event))

                # Clean up expired events outside window
                window_start = now_ts - rule.time_window_seconds
                self.event_buffers[rule.id][group_key] = [
                    (t, evt) for (t, evt) in buf if t >= window_start
                ]
                active_buf = self.event_buffers[rule.id][group_key]

                # Check if threshold count is reached
                if len(active_buf) >= rule.threshold_count:
                    cooldown_key = f"{rule.id}:{group_key}"
                    if now_ts - self.alert_cooldowns.get(cooldown_key, 0.0) > 20.0: # 20s cooldown
                        matched_events = [evt for (_, evt) in active_buf]
                        alert = self.alert_manager.create_alert(rule, matched_events, group_key=group_key)
                        self.alert_cooldowns[cooldown_key] = now_ts
                        self.metrics_engine.record_detection(alert)
                        generated_alerts.append(alert)
                        self._notify_listeners(alert)
                        # Reset buffer after alert match
                        self.event_buffers[rule.id][group_key] = []

        return generated_alerts

    def _get_group_key(self, event: LogEvent, group_by_field: Optional[str]) -> str:
        if not group_by_field:
            return event.hostname
        val = getattr(event, group_by_field, None) or event.details.get(group_by_field, "global")
        return str(val)

    def _notify_listeners(self, alert: DetectionAlert):
        for listener in self.alert_listeners:
            try:
                listener(alert)
            except Exception as e:
                print(f"[DetectionEngine Error] Alert callback error: {e}")

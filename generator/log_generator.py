import time
import random
import threading
from typing import List, Callable, Optional
from .models import LogEvent, ScenarioType
from .attack_simulators import (
    generate_brute_force_scenario,
    generate_privilege_escalation_scenario,
    generate_anomalous_process_scenario,
    generate_persistence_scenario,
    generate_lateral_movement_scenario,
    generate_data_exfiltration_scenario,
    generate_defense_evasion_scenario,
    generate_process_hollowing_scenario,
    generate_kernel_driver_tampering_scenario,
    generate_kerberoasting_scenario,
    generate_lsass_dump_scenario,
    generate_baseline_traffic
)

class TelemetryGenerator:
    """
    Manages continuous and scenario-driven log generation across virtual containerized hosts.
    Emits events to registered callback listeners (e.g. Detection Engine & WebSocket server).
    """

    def __init__(self):
        self.listeners: List[Callable[[LogEvent], None]] = []
        self.is_running = False
        self._thread: Optional[threading.Thread] = None

    def register_listener(self, listener: Callable[[LogEvent], None]):
        """Registers a callback to receive generated LogEvent instances."""
        if listener not in self.listeners:
            self.listeners.append(listener)

    def emit_event(self, event: LogEvent):
        """Dispatches event to all registered listeners."""
        for listener in self.listeners:
            try:
                listener(event)
            except Exception as e:
                print(f"[TelemetryGenerator Error] Callback failed: {e}")

    def emit_events(self, events: List[LogEvent]):
        """Dispatches a list of events with slight realistic delays between events."""
        for evt in events:
            self.emit_event(evt)
            time.sleep(0.05)  # Realistic rapid arrival burst

    def trigger_scenario(self, scenario: ScenarioType, **kwargs) -> List[LogEvent]:
        """Triggers a specific attack scenario and returns emitted events."""
        if scenario == ScenarioType.BRUTE_FORCE:
            events = generate_brute_force_scenario(**kwargs)
        elif scenario == ScenarioType.PRIVILEGE_ESCALATION:
            events = generate_privilege_escalation_scenario(**kwargs)
        elif scenario == ScenarioType.ANOMALOUS_PROCESS:
            events = generate_anomalous_process_scenario(**kwargs)
        elif scenario == ScenarioType.PERSISTENCE:
            events = generate_persistence_scenario(**kwargs)
        elif scenario == ScenarioType.LATERAL_MOVEMENT:
            events = generate_lateral_movement_scenario(**kwargs)
        elif scenario == ScenarioType.DATA_EXFILTRATION:
            events = generate_data_exfiltration_scenario(**kwargs)
        elif scenario == ScenarioType.DEFENSE_EVASION:
            events = generate_defense_evasion_scenario(**kwargs)
        elif scenario == ScenarioType.PROCESS_HOLLOWING:
            events = generate_process_hollowing_scenario(**kwargs)
        elif scenario == ScenarioType.KERNEL_DRIVER_TAMPERING:
            events = generate_kernel_driver_tampering_scenario(**kwargs)
        elif scenario == ScenarioType.KERBEROASTING:
            events = generate_kerberoasting_scenario(**kwargs)
        elif scenario == ScenarioType.LSASS_DUMP:
            events = generate_lsass_dump_scenario(**kwargs)
        elif scenario == ScenarioType.NORMAL_BASELINE:
            events = generate_baseline_traffic(**kwargs)
        else:
            events = generate_baseline_traffic(count=3)

        self.emit_events(events)
        return events

    def start_background_stream(self, interval_seconds: float = 3.0):
        """Starts a background thread generating baseline traffic intermittently."""
        if self.is_running:
            return

        self.is_running = True
        self._thread = threading.Thread(target=self._run_loop, args=(interval_seconds,), daemon=True)
        self._thread.start()

    def stop_background_stream(self):
        """Stops the background telemetry stream."""
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run_loop(self, interval: float):
        while self.is_running:
            # Emit baseline events randomly
            events = generate_baseline_traffic(count=random.randint(1, 3))
            self.emit_events(events)

            # Occasionally inject an organic attack scenario (10% chance per interval)
            if random.random() < 0.15:
                rand_scenario = random.choice([
                    ScenarioType.BRUTE_FORCE,
                    ScenarioType.PRIVILEGE_ESCALATION,
                    ScenarioType.ANOMALOUS_PROCESS
                ])
                self.trigger_scenario(rand_scenario)

            time.sleep(interval)

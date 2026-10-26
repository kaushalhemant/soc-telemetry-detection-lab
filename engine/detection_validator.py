import os
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import uuid

from generator.models import LogEvent, ScenarioType, LogType
from generator.attack_simulators import (
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
from engine.detection_engine import DetectionEngine
from engine.metrics import calculate_latency_ms


class DetectionValidator:
    """
    Deterministic Detection Validation Test Suite.
    Runs controlled, reproducible test scenarios against the detection engine,
    compares actual rule triggers against documented expected results,
    and honestly reports missed detections, unexpected alerts, and test outcomes.

    DISCLAIMER:
    These tests use controlled synthetic telemetry to validate detection rule logic.
    They do not represent real-world enterprise operational security efficacy.
    """

    def __init__(self, rules_dir_or_engine: Any = None, rules_dir: Optional[str] = None):
        if rules_dir_or_engine is not None and hasattr(rules_dir_or_engine, "process_event"):
            self.engine = rules_dir_or_engine
            self.rules_dir = rules_dir
        elif isinstance(rules_dir_or_engine, str):
            self.engine = None
            self.rules_dir = rules_dir_or_engine
        else:
            self.engine = None
            self.rules_dir = rules_dir

    def run_validation_suite(self, engine: Optional[DetectionEngine] = None) -> Dict[str, Any]:
        """
        Executes a deterministic suite of benign and attack test cases
        in an isolated sandbox engine instance.
        """
        # Create an isolated engine to avoid mutating production alert queues or cooldowns
        default_rules_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "rules"))
        target_engine = engine or self.engine

        if target_engine and target_engine.rules:
            test_engine = DetectionEngine()
            test_engine.rules = list(target_engine.rules)
            test_engine.rules_dir = target_engine.rules_dir or default_rules_dir
        else:
            r_dir = self.rules_dir or (target_engine.rules_dir if target_engine else None) or default_rules_dir
            test_engine = DetectionEngine(rules_dir=r_dir)
        
        # Define deterministic test scenarios
        test_cases = [
            {
                "id": "TC-001",
                "name": "SSH Credential Brute Force (Above Threshold)",
                "expected_rule_id": "RULE-001",
                "generator": lambda: generate_brute_force_scenario(num_failures=8, include_success=False),
                "is_attack": True,
                "description": "8 consecutive failed SSH authentication attempts from an attacker IP (exceeds threshold of 5)."
            },
            {
                "id": "TC-002",
                "name": "SSH Failed Logins (Below Threshold)",
                "expected_rule_id": None,
                "generator": lambda: generate_brute_force_scenario(num_failures=2, include_success=False),
                "is_attack": False,
                "description": "2 failed SSH authentication attempts (below threshold of 5). Should NOT generate an alert."
            },
            {
                "id": "TC-003",
                "name": "Privilege Escalation via SUID Manipulation",
                "expected_rule_id": "RULE-002",
                "generator": lambda: generate_privilege_escalation_scenario(),
                "is_attack": True,
                "description": "Unauthorized chmod u+s modification on shell executable resulting in effective root privileges."
            },
            {
                "id": "TC-004",
                "name": "Web Server Anomalous Reverse Shell Spawn",
                "expected_rule_id": "RULE-003",
                "generator": lambda: generate_anomalous_process_scenario(),
                "is_attack": True,
                "description": "Web daemon (nginx/www-data) spawning an interactive shell binary (/bin/sh)."
            },
            {
                "id": "TC-005",
                "name": "Crontab Scheduled Persistence",
                "expected_rule_id": "RULE-004",
                "generator": lambda: generate_persistence_scenario(),
                "is_attack": True,
                "description": "Crontab edit modifying scheduled cron table to execute a remote script."
            },
            {
                "id": "TC-006",
                "name": "Remote Execution Lateral Movement via WinRM",
                "expected_rule_id": "RULE-005",
                "generator": lambda: generate_lateral_movement_scenario(),
                "is_attack": True,
                "description": "Remote PowerShell command execution through Windows Remote Management (wsmprovhost)."
            },
            {
                "id": "TC-007",
                "name": "DNS TXT Query Data Exfiltration",
                "expected_rule_id": "RULE-006",
                "generator": lambda: generate_data_exfiltration_scenario(),
                "is_attack": True,
                "description": "High-frequency encoded DNS TXT queries directed at attacker-controlled nameservers."
            },
            {
                "id": "TC-008",
                "name": "Security Audit Log Clearing",
                "expected_rule_id": "RULE-007",
                "generator": lambda: generate_defense_evasion_scenario(),
                "is_attack": True,
                "description": "Deletion or unlinking of /var/log/auth.log audit trail."
            },
            {
                "id": "TC-009",
                "name": "Process Hollowing & Code Injection",
                "expected_rule_id": "RULE-008",
                "generator": lambda: generate_process_hollowing_scenario(),
                "is_attack": True,
                "description": "Memory unmapping (NtUnmapViewOfSection) and injection into suspended svchost.exe."
            },
            {
                "id": "TC-010",
                "name": "BYOVD Vulnerable Kernel Driver Load",
                "expected_rule_id": "RULE-009",
                "generator": lambda: generate_kernel_driver_tampering_scenario(),
                "is_attack": True,
                "description": "Loading vulnerable signed driver (RTCore64.sys) to tamper with kernel callbacks."
            },
            {
                "id": "TC-011",
                "name": "Active Directory Kerberoasting TGS Request",
                "expected_rule_id": "RULE-010",
                "generator": lambda: generate_kerberoasting_scenario(),
                "is_attack": True,
                "description": "Kerberos TGS request querying Service Principal Name with weak RC4-HMAC encryption."
            },
            {
                "id": "TC-012",
                "name": "LSASS Memory Credential Dumping",
                "expected_rule_id": "RULE-011",
                "generator": lambda: generate_lsass_dump_scenario(),
                "is_attack": True,
                "description": "Memory dump of lsass.exe via comsvcs.dll MiniDump."
            },
            {
                "id": "TC-013",
                "name": "Normal Benign Baseline Traffic (Zero FP Test)",
                "expected_rule_id": None,
                "generator": lambda: generate_baseline_traffic(count=20),
                "is_attack": False,
                "description": "20 benign HTTP and SSH authentication events. Expects zero security alerts."
            }
        ]

        scenario_results = []
        tp_count = 0
        fp_count = 0
        fn_count = 0
        tn_count = 0
        latencies: List[float] = []

        start_time = time.perf_counter()

        for tc in test_cases:
            # Clear sandbox buffers between scenarios for isolated reproducibility
            test_engine.event_buffers.clear()
            test_engine.alert_cooldowns.clear()
            test_engine.event_watermarks.clear()

            events = tc["generator"]()
            triggered_alerts = []

            for evt in events:
                alerts = test_engine.process_event(evt)
                if alerts:
                    triggered_alerts.extend(alerts)

            triggered_rule_ids = [a.rule_id for a in triggered_alerts]
            expected_rule_id = tc["expected_rule_id"]

            if expected_rule_id:
                # Expecting an alert
                detected = expected_rule_id in triggered_rule_ids
                unexpected = [r for r in triggered_rule_ids if r != expected_rule_id]
                passed = detected and len(unexpected) == 0

                if detected:
                    tp_count += 1
                else:
                    fn_count += 1

                if unexpected:
                    fp_count += len(unexpected)

                # Compute latency from first triggering alert
                matched_alert = next((a for a in triggered_alerts if a.rule_id == expected_rule_id), None)
                tc_latency = None
                if matched_alert and events:
                    tc_latency = calculate_latency_ms(events[-1].timestamp, matched_alert.timestamp)
                    if tc_latency is not None:
                        latencies.append(tc_latency)

            else:
                # Expecting NO alert (benign baseline or below threshold)
                unexpected = triggered_rule_ids
                passed = len(unexpected) == 0

                if passed:
                    tn_count += 1
                else:
                    fp_count += len(unexpected)
                tc_latency = None

            scenario_results.append({
                "test_id": tc["id"],
                "name": tc["name"],
                "description": tc["description"],
                "is_attack": tc["is_attack"],
                "events_count": len(events),
                "expected_rule_id": expected_rule_id or "NONE (No Alert)",
                "actual_rules_triggered": triggered_rule_ids or ["NONE"],
                "passed": passed,
                "missed_detection": (expected_rule_id is not None and expected_rule_id not in triggered_rule_ids),
                "unexpected_alerts": [r for r in triggered_rule_ids if r != expected_rule_id],
                "latency_ms": tc_latency
            })

        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        total_scenarios = len(test_cases)
        passed_scenarios = sum(1 for r in scenario_results if r["passed"])
        failed_scenarios = total_scenarios - passed_scenarios

        # Calculate performance metrics strictly on this deterministic run
        precision = round((tp_count / (tp_count + fp_count)) * 100.0, 1) if (tp_count + fp_count) > 0 else None
        recall = round((tp_count / (tp_count + fn_count)) * 100.0, 1) if (tp_count + fn_count) > 0 else None
        fpr = round((fp_count / (fp_count + tn_count)) * 100.0, 2) if (fp_count + tn_count) > 0 else None
        mean_mttd = round(sum(latencies) / len(latencies), 2) if latencies else None

        return {
            "validation_timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_time_ms": elapsed_ms,
            "total_scenarios": total_scenarios,
            "passed_scenarios": passed_scenarios,
            "failed_scenarios": failed_scenarios,
            "pass_rate_pct": round((passed_scenarios / total_scenarios) * 100.0, 1) if total_scenarios > 0 else 0.0,
            "confusion_matrix": {
                "true_positives": tp_count,
                "false_positives": fp_count,
                "false_negatives": fn_count,
                "true_negatives": tn_count
            },
            "metrics": {
                "precision_pct": precision,
                "recall_pct": recall,
                "false_positive_rate_pct": fpr,
                "mttd_ms": mean_mttd,
                "sample_size": tp_count + fp_count + fn_count + tn_count
            },
            "scenarios": scenario_results,
            "disclaimer": "Deterministic laboratory validation test using controlled synthetic telemetry; demonstrates detection rule logic correctness in a sandbox environment and is not a guarantee of real-world enterprise detection efficacy."
        }

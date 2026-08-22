import os
import glob
import yaml
from typing import Dict, Any, List, Optional
from generator.models import LogEvent, SeverityLevel

class Rule:
    """
    Parsed SIGMA-style Detection Rule object.
    """
    def __init__(self, raw_data: Dict[str, Any]):
        self.id: str = raw_data.get("id", "RULE-UNKNOWN")
        self.title: str = raw_data.get("title", "Untitled Detection Rule")
        self.description: str = raw_data.get("description", "")
        self.status: str = raw_data.get("status", "experimental")
        self.severity: SeverityLevel = SeverityLevel(raw_data.get("severity", "MEDIUM").upper())
        self.log_type: str = raw_data.get("log_source", {}).get("log_type", "")
        
        self.detection: Dict[str, Any] = raw_data.get("detection", {})
        self.selection: Dict[str, Any] = self.detection.get("selection", {})
        self.time_window_seconds: int = self.detection.get("time_window_seconds", 60)
        
        # Threshold logic
        threshold_cfg = self.detection.get("threshold", {})
        self.threshold_count: int = threshold_cfg.get("count", 1)
        self.threshold_group_by: Optional[str] = threshold_cfg.get("group_by", None)

        # MITRE Tags
        tags = raw_data.get("tags", {})
        self.mitre_tactic: str = tags.get("mitre_tactic", "Initial Access")
        self.mitre_technique_id: str = tags.get("mitre_technique_id", "T1000")
        self.mitre_technique_name: str = tags.get("mitre_technique_name", "General Technique")
        
        self.remediation: List[str] = raw_data.get("remediation", [])
        self.raw_dict = raw_data

    def matches_single_event(self, event: LogEvent) -> bool:
        """
        Evaluates whether a single LogEvent satisfies rule selection logic.
        """
        # 1. Log type match check
        if self.log_type and event.log_type.value != self.log_type:
            return False

        # 2. Selection criteria match
        for key, expected_value in self.selection.items():
            actual_value = getattr(event, key, None)
            if actual_value is None and hasattr(event, "details"):
                actual_value = event.details.get(key)
            
            if isinstance(expected_value, list):
                if actual_value not in expected_value:
                    return False
            else:
                if actual_value != expected_value:
                    return False

        # 3. Custom condition criteria check if present
        conditions = self.detection.get("condition", [])
        if isinstance(conditions, list):
            for cond in conditions:
                field_path = cond.get("field", "")
                operator = cond.get("operator", "equals")
                target_val = cond.get("value")

                val = self._extract_field(event, field_path)
                if not self._eval_operator(val, operator, target_val):
                    return False

        return True

    def _extract_field(self, event: LogEvent, field_path: str) -> Any:
        parts = field_path.split(".")
        curr = event
        for part in parts:
            if isinstance(curr, LogEvent):
                curr = getattr(curr, part, None) or getattr(curr, "details", {}).get(part)
            elif isinstance(curr, dict):
                curr = curr.get(part)
            else:
                return None
        return curr

    def _eval_operator(self, actual: Any, operator: str, target: Any) -> bool:
        if actual is None:
            return False
        if operator == "equals":
            return actual == target
        elif operator == "in":
            if isinstance(target, list):
                return actual in target
            return str(actual) in str(target)
        elif operator == "greater_than":
            return actual > target
        elif operator == "contains":
            return str(target).lower() in str(actual).lower()
        return False

def load_rules_from_directory(directory_path: str) -> List[Rule]:
    """Loads all .yml and .yaml rules from a given directory."""
    rules = []
    yaml_files = glob.glob(os.path.join(directory_path, "*.yml")) + glob.glob(os.path.join(directory_path, "*.yaml"))
    for file_path in yaml_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
                if content:
                    rules.append(Rule(content))
        except Exception as e:
            print(f"[RuleParser Error] Failed to load rule {file_path}: {e}")
    return rules

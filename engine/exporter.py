from typing import Dict, Any, List
from .rule_parser import Rule

class SigmaExporter:
    """
    Translates SIGMA YAML rules into target deployment backends:
    - Splunk Search Processing Language (SPL)
    - Elastic Query DSL / KQL
    - MITRE ATT&CK Navigator Layer JSON
    """

    @staticmethod
    def to_splunk(rule: Rule) -> str:
        """Compiles a Rule into Splunk SPL syntax."""
        index = "index=security"
        log_type = f'log_type="{rule.log_type}"' if rule.log_type else ""
        
        selection_parts = []
        for k, v in rule.selection.items():
            if isinstance(v, list):
                or_vals = " OR ".join([f'{k}="{val}"' for val in v])
                selection_parts.append(f'({or_vals})')
            else:
                selection_parts.append(f'{k}="{v}"')
        
        sel_query = " AND ".join(selection_parts)
        base_query = f"{index} {log_type} {sel_query}".strip()
        
        if rule.threshold_count > 1:
            group_field = rule.threshold_group_by or "source_ip"
            base_query += f' | stats count by {group_field} | where count >= {rule.threshold_count}'
            
        return base_query

    @staticmethod
    def to_elastic(rule: Rule) -> str:
        """Compiles a Rule into Elastic KQL syntax."""
        terms = []
        if rule.log_type:
            terms.append(f'log_type: "{rule.log_type}"')
            
        for k, v in rule.selection.items():
            if isinstance(v, list):
                or_vals = " OR ".join([f'{k}: "{val}"' for val in v])
                terms.append(f'({or_vals})')
            else:
                terms.append(f'{k}: "{v}"')
                
        kql = " AND ".join(terms)
        return kql

    @staticmethod
    def generate_mitre_navigator_layer(rules: List[Rule]) -> Dict[str, Any]:
        """Generates an official ATT&CK Navigator v4.5 Layer JSON export."""
        techniques = []
        for r in rules:
            if r.mitre_technique_id:
                tech_id = r.mitre_technique_id.split('.')[0]  # Base technique ID
                score = 100 if r.severity == "CRITICAL" else 75 if r.severity == "HIGH" else 50
                techniques.append({
                    "techniqueID": tech_id,
                    "tactic": r.mitre_tactic.lower().replace(" ", "-") if r.mitre_tactic else "execution",
                    "score": score,
                    "color": "#f85149" if score == 100 else "#d97706" if score == 75 else "#eab308",
                    "comment": f"Rule: {r.id} - {r.title} ({r.severity})",
                    "enabled": True
                })

        return {
            "name": "SOC Telemetry Detection Lab - Coverage Heatmap",
            "versions": {
                "attack": "14",
                "navigator": "4.5"
            },
            "domain": "enterprise-attack",
            "description": "Detection rule coverage layer compiled directly from active SIGMA rules.",
            "filters": {
                "platforms": ["Linux", "Windows", "Containers"]
            },
            "sorting": 3,
            "layout": {
                "layout": "flat",
                "showID": True,
                "showName": True
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#161b22", "#d97706", "#f85149"],
                "minValue": 0,
                "maxValue": 100
            }
        }

"""Small transparent mapping layer; Wazuh rule metadata takes precedence."""
from __future__ import annotations

MAPPINGS = {
    "brute": ("Credential Access", "Brute Force", "T1110"),
    "scan": ("Discovery", "Network Service Scanning", "T1046"),
    "command": ("Execution", "Command and Scripting Interpreter", "T1059"),
    "fim": ("Impact", "File and Directory Discovery / change review", "T1083"),
    "persistence": ("Persistence", "Create or Modify System Process", "T1543"),
    "cowrie": ("Initial Access", "External Remote Services", "T1133"),
}


def map_alert(alert: dict) -> list[dict[str, str]]:
    explicit = alert.get("mitre_ids", [])
    if explicit:
        return [{"tactic": "Declared by Wazuh rule", "technique": "See rule metadata", "id": item} for item in explicit]
    text = " ".join([alert.get("description", ""), *alert.get("groups", [])]).lower()
    return [{"tactic": tactic, "technique": technique, "id": tid} for key, (tactic, technique, tid) in MAPPINGS.items() if key in text]

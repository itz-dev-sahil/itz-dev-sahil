from __future__ import annotations
from datetime import datetime, timezone
import hashlib


def create_incident(alert: dict, iocs: dict, techniques: list[dict], risk: dict) -> dict:
    seed = f"{alert['timestamp']}|{alert['rule_id']}|{alert['source_ip']}"
    incident_id = "INC-" + hashlib.sha256(seed.encode()).hexdigest()[:10].upper()
    return {"incident_id": incident_id, "timestamp": alert["timestamp"] or datetime.now(timezone.utc).isoformat(), "severity": risk["severity"], "risk_score": risk["score"], "source_ip": alert["source_ip"], "affected_host": alert["affected_host"], "username": alert["username"], "techniques": techniques, "iocs": iocs, "evidence": [{"rule_id": alert["rule_id"], "description": alert["description"]}], "status": "NEW", "recommendation": "Validate the alert, preserve relevant logs, scope related activity, and contain only after authorization.", "risk_rationale": risk["reasons"]}

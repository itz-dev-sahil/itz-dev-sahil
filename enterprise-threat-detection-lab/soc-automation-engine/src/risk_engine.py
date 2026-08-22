"""Explainable heuristic, not a scientifically validated threat score."""
from __future__ import annotations


def score_alert(alert: dict, related_count: int = 0, malicious_reputation: bool = False, critical_asset: bool = False) -> dict:
    points = min(alert.get("rule_level", 0) * 5, 50)
    reasons = [f"Wazuh rule level {alert.get('rule_level', 0)} contributes {points} points"]
    if related_count >= 5:
        points += 20; reasons.append("five or more related alerts contribute 20 points")
    elif related_count >= 2:
        points += 10; reasons.append("multiple related alerts contribute 10 points")
    if malicious_reputation:
        points += 25; reasons.append("malicious reputation contributes 25 points")
    if critical_asset:
        points += 15; reasons.append("critical asset contributes 15 points")
    severity = "CRITICAL" if points >= 80 else "HIGH" if points >= 55 else "MEDIUM" if points >= 25 else "LOW"
    return {"score": min(points, 100), "severity": severity, "reasons": reasons}

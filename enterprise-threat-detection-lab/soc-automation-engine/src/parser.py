"""Normalization layer for Wazuh-compatible JSON alerts."""
from __future__ import annotations
from typing import Any


def dig(data: dict[str, Any], *path: str, default: Any = None) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default


def normalize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    rule = alert.get("rule", {})
    data = alert.get("data", {})
    return {
        "timestamp": alert.get("timestamp", ""),
        "rule_id": str(rule.get("id", "unknown")),
        "rule_level": int(rule.get("level", 0)),
        "description": rule.get("description", "Unclassified alert"),
        "groups": rule.get("groups", []),
        "mitre_ids": dig(rule, "mitre", "id", default=[]),
        "source_ip": data.get("srcip") or dig(alert, "srcip", default=""),
        "affected_host": dig(alert, "agent", "name", default="wazuh-manager"),
        "username": data.get("username") or data.get("user") or "",
        "raw": alert,
    }

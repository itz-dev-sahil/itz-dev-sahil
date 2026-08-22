from __future__ import annotations
from collections import Counter


def related_count(normalized: dict, alerts: list[dict]) -> int:
    """Correlate by matching non-empty source IP, host, or username in supplied batch."""
    keys = [("source_ip", normalized.get("source_ip")), ("affected_host", normalized.get("affected_host")), ("username", normalized.get("username"))]
    count = 0
    for candidate in alerts:
        if any(value and candidate.get(field) == value for field, value in keys):
            count += 1
    return count


def hunting_summary(alerts: list[dict]) -> dict:
    return {"top_source_ips": Counter(a.get("source_ip") for a in alerts if a.get("source_ip")).most_common(), "top_users": Counter(a.get("username") for a in alerts if a.get("username")).most_common()}

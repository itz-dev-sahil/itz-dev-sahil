"""Validated IOC extraction for controlled-lab alert data."""
from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_CANDIDATE_RE = re.compile(r"(?<![\w:.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])|(?<![\w:])[0-9a-fA-F:]{2,}(?![\w:])")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")
PATH_RE = re.compile(r"(?:/(?:[^\s\"']+/?)+|[A-Za-z]:\\(?:[^\s\"']+\\?)+)")


def _walk(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [item for child in value.values() for item in _walk(child)]
    if isinstance(value, list):
        return [item for child in value for item in _walk(child)]
    return [str(value)] if value is not None else []


def _unique(values: list[str]) -> list[str]:
    return sorted(set(values))


def _values_for_keys(value: Any, keys: set[str]) -> list[str]:
    if isinstance(value, dict):
        found = [str(item) for key, item in value.items() if key.lower() in keys and item is not None]
        return found + [item for child in value.values() for item in _values_for_keys(child, keys)]
    if isinstance(value, list):
        return [item for child in value for item in _values_for_keys(child, keys)]
    return []


def extract_iocs(alert: dict[str, Any]) -> dict[str, list[str]]:
    """Extract conservative, structured IOCs from arbitrary alert JSON."""
    text = "\n".join(_walk(alert))
    urls = _unique(URL_RE.findall(text))
    valid_ips: list[str] = []
    for candidate in IP_CANDIDATE_RE.findall(text):
        try:
            parsed = ipaddress.ip_address(candidate)
            if not (parsed.is_loopback or parsed.is_unspecified):
                valid_ips.append(str(parsed))
        except ValueError:
            continue
    domains = [d.lower() for d in DOMAIN_RE.findall(text) if not d.lower().endswith((".local", ".internal"))]
    domains.extend(urlparse(url).hostname or "" for url in urls)
    usernames = _unique(_values_for_keys(alert, {"user", "username", "account"}) + re.findall(r"(?:user(?:name)?|account)\s*[=:]\s*([A-Za-z0-9_.-]{1,64})", text, re.I))
    hostnames = _unique(_values_for_keys(alert, {"hostname", "host", "name"}) + re.findall(r"(?:host(?:name)?|agent\.name)\s*[=:]\s*([A-Za-z0-9_.-]{1,253})", text, re.I))
    return {
        "ip_addresses": _unique(valid_ips),
        "domains": _unique([d for d in domains if d]),
        "urls": urls,
        "hashes": _unique(HASH_RE.findall(text)),
        "usernames": usernames,
        "hostnames": hostnames,
        "file_paths": _unique(PATH_RE.findall(text)),
    }

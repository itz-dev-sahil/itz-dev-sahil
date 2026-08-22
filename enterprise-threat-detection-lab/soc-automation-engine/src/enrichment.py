"""Offline-first enrichment. Network lookups are intentionally not automatic."""
from __future__ import annotations
import os


def enrich(iocs: dict) -> dict:
    return {"enabled": bool(os.getenv("VT_API_KEY")), "provider": "VirusTotal" if os.getenv("VT_API_KEY") else "none", "note": "No network enrichment performed; add an audited provider client before enabling API requests.", "iocs_reviewed": iocs.get("ip_addresses", []) + iocs.get("hashes", [])}

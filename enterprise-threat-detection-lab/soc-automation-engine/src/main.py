from __future__ import annotations
import argparse, json
from pathlib import Path
from parser import normalize_alert
from ioc_extractor import extract_iocs
from mitre_mapper import map_alert
from risk_engine import score_alert
from correlation import related_count
from enrichment import enrich
from incident import create_incident
from reporter import write_report

def main() -> None:
    p = argparse.ArgumentParser(description="Offline-first Wazuh alert triage for an authorized lab")
    p.add_argument("alert", type=Path, help="Path to one Wazuh JSON alert")
    p.add_argument("--output", type=Path, default=Path("data/output"))
    args = p.parse_args()
    raw = json.loads(args.alert.read_text(encoding="utf-8"))
    alerts = raw if isinstance(raw, list) else [raw]
    current = normalize_alert(alerts[0])
    normalized_batch = [normalize_alert(a) for a in alerts]
    iocs = extract_iocs(alerts[0]); risk = score_alert(current, related_count(current, normalized_batch))
    incident = create_incident(current, iocs, map_alert(current), risk)
    incident["enrichment"] = enrich(iocs)
    paths = write_report(incident, args.output)
    print(f"Created {paths[0]} and {paths[1]}")
if __name__ == "__main__": main()

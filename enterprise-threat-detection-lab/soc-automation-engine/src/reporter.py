from __future__ import annotations
from pathlib import Path
import json


def write_report(incident: dict, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"{incident['incident_id']}.json"
    md_path = output_dir / f"{incident['incident_id']}.md"
    json_path.write_text(json.dumps(incident, indent=2) + "\n", encoding="utf-8")
    techniques = ", ".join(f"{x['id']} ({x['technique']})" for x in incident['techniques']) or "Requires analyst mapping"
    md_path.write_text(f"# Incident {incident['incident_id']}\n\n## Executive summary\nA controlled-lab alert was triaged as **{incident['severity']}** (risk score: {incident['risk_score']}/100).\n\n## Evidence\n- **Time:** {incident['timestamp']}\n- **Host:** {incident['affected_host']}\n- **Source IP:** {incident['source_ip'] or 'Not available'}\n- **Rule:** {incident['evidence'][0]['rule_id']} — {incident['evidence'][0]['description']}\n\n## MITRE ATT&CK\n{techniques}\n\n## Recommended response\n{incident['recommendation']}\n\n## Risk rationale\n" + "\n".join(f"- {reason}" for reason in incident['risk_rationale']) + "\n", encoding="utf-8")
    return json_path, md_path

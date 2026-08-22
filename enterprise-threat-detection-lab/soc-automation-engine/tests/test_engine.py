import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))
from ioc_extractor import extract_iocs
from parser import normalize_alert
from risk_engine import score_alert
from incident import create_incident

def fixture():
    return json.loads((Path(__file__).parents[1] / "data/sample_alerts/cowrie-bruteforce.json").read_text())

def test_extracts_valid_ip_and_rejects_loopback():
    iocs = extract_iocs({"message": "source 172.28.0.30 and 127.0.0.1"})
    assert iocs["ip_addresses"] == ["172.28.0.30"]
    assert extract_iocs(fixture())["usernames"] == ["labuser"]

def test_creates_explainable_high_incident():
    alert = normalize_alert(fixture())
    risk = score_alert(alert, related_count=5)
    incident = create_incident(alert, extract_iocs(fixture()), [], risk)
    assert risk["severity"] == "HIGH"
    assert incident["incident_id"].startswith("INC-")

# SOC Automation Engine

An offline-first Python triage utility for **authorized lab** Wazuh JSON alerts. It normalizes alerts, extracts validated indicators, honors Wazuh MITRE metadata, calculates an explainable heuristic risk score, and writes JSON and Markdown incident artifacts.

## Run

```bash
cd soc-automation-engine
python src/main.py data/sample_alerts/cowrie-bruteforce.json --output data/output
python -m pytest tests
```

The engine has no runtime third-party dependencies. API keys are deliberately optional and must be supplied through environment variables (for example, `VT_API_KEY`), never committed.

## Scoring

The score is a transparent lab heuristic: Wazuh level × 5 (capped at 50), plus 10/20 for related activity, 25 for confirmed malicious reputation, and 15 for a critical asset. Scores map to LOW (<25), MEDIUM (25–54), HIGH (55–79), or CRITICAL (80+). It is not a validated threat-risk model.

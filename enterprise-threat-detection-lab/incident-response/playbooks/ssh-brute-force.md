# Playbook: Controlled SSH Brute-Force Alert

1. Confirm the alert source is the authorized lab simulator and record the case ID.
2. Preserve Cowrie event JSON, Wazuh alert JSON, timestamps, source IP, targeted usernames, and session identifiers.
3. Determine whether failures were followed by a successful honeypot login or commands.
4. Correlate events by source IP and time window; do not block a source until the lab owner authorizes containment.
5. In the lab, contain by stopping the simulator or disconnecting the isolated test network; document the action.
6. Validate alert closure, record rule tuning opportunities, and retain only sanitized evidence in Git.

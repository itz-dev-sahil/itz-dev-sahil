# Troubleshooting

## Cowrie does not start
Check Docker container logs and ensure port `2222` is not already bound. The loopback binding is intentional; do not replace it with a public `0.0.0.0` binding.

## Wazuh alerts do not appear
Validate event format with `wazuh-logtest`, then confirm the decoder fields match actual Cowrie JSON. Check the agent/forwarder connection, manager logs, rule XML syntax, and custom-rule deployment path. Restart only after preserving diagnostic logs.

## Rule does not match
Test one raw event first. Confirm the exact JSON key (`eventid`, source field, etc.), parent rule match, frequency threshold, and time window. Custom fields must be validated in your Wazuh release.

## Python reports are missing
Run the command from `soc-automation-engine`, ensure the source JSON is valid, and verify that `data/output` is writable. The starter engine uses the standard library, so dependency failures should not block it.

## API enrichment is unavailable
The engine continues without API keys by design. Do not put secrets in configuration files or Git. Add a provider client only after reviewing rate limits, privacy implications, and API documentation.

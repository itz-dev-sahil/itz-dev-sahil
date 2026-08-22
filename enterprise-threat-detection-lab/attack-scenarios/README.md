# Controlled Scenario Catalog

All scenarios target only the `soc_lab_net` environment. Do not route test activity to a home LAN, public address, employer system, or any target you do not explicitly control.

| ID | Scenario | Safe evidence | Expected detection |
|---|---|---|---|
| SCN-01 | SSH authentication failures | Cowrie `cowrie.login.failed` events | Custom Wazuh rule `100101`; repeated activity `100102` / T1110 |
| SCN-02 | Service-discovery simulation | Lab-only connection telemetry or fixture | T1046 investigation workflow |
| SCN-03 | Harmless discovery command in Cowrie | `cowrie.command.input` JSON | Rule `100103` / T1059 |
| SCN-04 | Monitored-file create/modify/delete | Wazuh FIM events | FIM alert and authorization review |
| SCN-05 | Safe persistence-indicator configuration file | FIM event for a non-executing lab file | Review against T1543 |
| SCN-06 | EICAR test artifact | YARA match only | `Lab_EICAR_Test_File` |

Use the supplied sample alert to exercise automation without sending any network traffic.

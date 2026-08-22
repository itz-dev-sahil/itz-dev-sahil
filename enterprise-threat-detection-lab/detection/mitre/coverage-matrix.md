# MITRE ATT&CK Coverage Matrix

| Controlled scenario | Tactic | Technique | ID | Detection | Initial response |
|---|---|---|---|---|---|
| Repeated failed SSH attempts | Credential Access | Brute Force | T1110 | Wazuh Cowrie rule `100102` | Validate source, session volume, and any successful follow-on login. |
| Lab port/service scan evidence | Discovery | Network Service Scanning | T1046 | Future network telemetry rule | Confirm scope and check correlated authentication attempts. |
| Command entered in Cowrie | Execution | Command and Scripting Interpreter | T1059 | Wazuh Cowrie rule `100103` | Preserve session evidence; assess command intent. |
| Safe persistence-indicator file | Persistence | Create or Modify System Process | T1543 | FIM/custom rule after validation | Verify change ownership and remove only after approval. |
| File-change evidence | Discovery / analyst review | File and Directory Discovery | T1083 | Wazuh FIM | Compare hashes and establish whether the change was authorized. |

Mappings must be checked against the current MITRE ATT&CK release during integration. The file-change row is intentionally an investigation context, not a claim that every file modification is T1083.

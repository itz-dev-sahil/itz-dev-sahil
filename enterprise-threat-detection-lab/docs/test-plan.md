# Test Plan

| Test ID | Scenario | Expected event | Expected detection | MITRE | Expected severity | Expected response | Result |
|---|---|---|---|---|---|---|---|
| T-01 | Repeated SSH failures | Five Cowrie failed-logon events in 120 seconds | Rule `100102` after validation | T1110 | High | Preserve, scope, authorized containment | Pending Wazuh validation |
| T-02 | Command input | Cowrie command-input event | Rule `100103` | T1059 | High | Preserve session and triage intent | Pending Wazuh validation |
| T-03 | EICAR artifact | YARA signature match | `Lab_EICAR_Test_File` | N/A | Medium | Isolate/remove test artifact after validation | Pending environment setup |
| T-04 | Sample alert processing | JSON report and Markdown report | Python engine output | T1110 from alert metadata | Medium | New incident generated | Automated test |

A test is marked verified only after its evidence is recorded. `Pending` does not mean detected.

# Low-Resource Architecture

```mermaid
flowchart LR
  K[Kali simulator container\nauthorized activity only] --> C[Cowrie SSH honeypot\ninternal Docker network]
  C -->|JSON events| W[Wazuh manager\ndedicated node]
  E[Optional Windows agent] --> W
  W -->|JSON alerts| P[Python SOC engine]
  P --> R[Incident JSON + Markdown report]
```

The local Docker network is internal and Cowrie is bound only to `127.0.0.1:2222`. A separate Wazuh node is required for the manager, indexer, and dashboard because the project host has 8 GB RAM.

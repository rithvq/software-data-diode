# Faculty Demonstration

This is the preserved HTTP/legacy demonstration. For the isolated RCCD research
mechanism use the [N11 local runbook](novelty-roadmap/local-demo.md) and
[faculty explanation](novelty-roadmap/faculty-explanation.md). Do not merge the
two deployments or substitute their state/keys. N10's negative findings remain
part of the research presentation.

Allow about 12 minutes. Run commands from the repository root.

## Before the Session

```powershell
.\.venv\Scripts\python.exe scripts\setup.py
.\.venv\Scripts\python.exe scripts\validate_config.py
docker compose --profile full up --build -d
docker compose --profile full ps
```

Wait until services report healthy. Open:

- Streamlit: http://127.0.0.1:8501
- Grafana: http://127.0.0.1:3000
- Fog Prometheus targets: http://127.0.0.1:9090/targets
- Edge Prometheus targets: http://127.0.0.1:9091/targets

## Demonstration Sequence

Run:

```powershell
.\.venv\Scripts\python.exe scripts\demo.py
```

The script prints and executes:

1. Normal telemetry
2. HIGH alert
3. CRITICAL security event
4. Tampered message
5. Replay attempt
6. Traffic congestion
7. Adaptive scheduler response
8. Fog anomaly

It stores machine-readable evidence in `demo-results/latest.json`. Point out the
five active device identities, priority metrics, bounded queue behavior,
security rejection, anomaly/alert tables, and the shared message correlation
identifier in JSON logs.

## Isolation Evidence

```powershell
.\scripts\inspect_networks.ps1 -ProjectName software-data-diode
docker compose --profile full exec -T fog-receiver python -c "import socket; socket.gethostbyname('edge-gateway')"
```

The second command must fail. Explain that this is logical Docker isolation:
the Fog Receiver is absent from Edge networks, and no reverse application API
exists.

## Security and Audit Evidence

Run the disposable attack suite after the full stack has been stopped:

```powershell
docker compose --profile full down
.\scripts\run_security_tests.ps1
```

Show `security-reports/security-test-results.csv` and
`security-reports/network-memberships.json`. Demonstrate an audit modification
against a copy:

```powershell
.\scripts\export_audit_logs.ps1
.\.venv\Scripts\python.exe scripts\tamper_audit_log.py logs\fog-receiver-audit.jsonl security-reports\faculty-tampered-audit.jsonl
.\.venv\Scripts\python.exe scripts\verify_audit_log.py security-reports\faculty-tampered-audit.jsonl
```

The verifier reports the first broken hash-chain line.

## Research Evidence

Open `experiments/results/phase7/experiment_summary.md` and the figures folder.
Explain the paired traces, five runs per configuration, confidence intervals,
baselines, and ablations. State measurements objectively.

## Required Closing Statement

The system is a software-defined/logically enforced unidirectional gateway
prototype. It demonstrates architectural isolation and security mechanisms but
cannot provide the absolute physical unidirectionality guarantees associated
with hardware data diodes.

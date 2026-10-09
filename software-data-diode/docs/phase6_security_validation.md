# Phase 6 Security Validation

Phase 6 adds repeatable adversarial tests without exposing any service to an
external network. The `security-test-client` is disabled in normal Compose runs
and exists only in the `security-test` profile.

## Trust Boundaries

The normal architecture is unchanged. Edge services use `edge-network`, the
gateway and diode share `diode-network`, the diode and receiver share
`fog-ingress-network`, and Fog processing uses `fog-services-network`.

During the controlled test profile only, the simulator joins `diode-network` and
`fog-ingress-network` so it can exercise the two intentional ingress APIs. It does
not join `edge-network` or `fog-services-network`. Both attached networks are
Docker `internal` networks, and the client additionally rejects every target URL
except the literal hosts `data-diode` and `fog-receiver`.

The private signing key is mounted read-only into the simulator only while this
test profile runs. That deliberate test capability is why the profile must never
be used as a production deployment profile. The normal stack still mounts the
private key only into the Edge Gateway.

## Run All Scenarios

Stop another copy of this project first, then run from the repository root:

```powershell
.\scripts\run_security_tests.ps1
```

The script uses the separate Compose project
`software-data-diode-security`, builds a deterministic low-capacity test stack,
runs the attacks, calls `docker network inspect`, saves evidence, and removes the
test containers and volumes. Network inspection occurs while the Edge and Fog
services are still running. The script never sends traffic outside the isolated
Compose networks.

The simulator covers:

| Scenario | Expected result |
|---|---|
| Signed payload modified after signing | `HASH_MISMATCH` |
| Signature modified | `INVALID_SIGNATURE` |
| New UUID with old sequence | `REPLAY_DETECTED` |
| Exact UUID reused | `DUPLICATE_MESSAGE` |
| Stale signed timestamp | `EXPIRED_MESSAGE` |
| Missing required envelope fields | `INVALID_SCHEMA` |
| Body above the diode limit | `PAYLOAD_TOO_LARGE` |
| Message flood | rate limiting and a bounded queue |
| LOW queue exhaustion | LOW drops while CRITICAL reaches Fog |
| Fog-to-Edge probe | every fixed resolution and connection attempt fails |
| Audit copy modified | verifier reports the first broken chain line |

## Reports

Generated files are written to `security-reports/`:

```text
security-test-results.csv
security-metrics.json
reverse-path-results.json
network-memberships.json
tampered-fog-receiver-audit.jsonl
```

The CSV columns are `scenario`, `attack_type`, `expected_result`,
`actual_result`, `detected`, `response_time`, and `timestamp`. The JSON metrics
include attack detection rate, false rejection rate, mean detection latency,
valid throughput during attacks, observed maximum queue size, LOW drops, and
CRITICAL latency during the flood.

## Manual Network Evidence

With a stack running, inspect its actual memberships:

```powershell
.\scripts\inspect_networks.ps1 -ProjectName software-data-diode
docker network inspect software-data-diode_edge-network
docker network inspect software-data-diode_fog-services-network
```

The Fog Receiver has no endpoint on `edge-network`, while Edge devices and the
Gateway have no endpoint on `fog-services-network`. Docker's embedded DNS is
network-scoped, so the Fog Receiver cannot resolve the Edge service names and has
no route to their service ports. The automated probe runs inside the Fog Receiver
itself, not from the host.

## Manual Audit Tamper Check

The source audit log is never modified. To attack a copy and report its first
broken location:

```powershell
.\scripts\export_audit_logs.ps1
.\.venv\Scripts\python.exe scripts\tamper_audit_log.py logs\fog-receiver-audit.jsonl security-reports\manual-tampered-audit.jsonl
.\.venv\Scripts\python.exe scripts\verify_audit_log.py security-reports\manual-tampered-audit.jsonl
```

## Scope

This validates controls in a software-emulated topology. A privileged Docker host
administrator can change container networks and mounts, so these tests do not
claim the physical one-way guarantee of a hardware data diode.

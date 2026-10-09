# Codebase Audit: 2026-09-23

## Scope and Result

Audited `C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode`, not `fog_edge_prj`.
The work covered the existing full stack, standalone Phase 1/2 pipelines, shared modules,
dashboard, deployment scripts, security simulator, and both experiment runners.
Confirmed defects were fixed and regression tests added. This is not a certification
that every possible defect has been eliminated or that every execution branch was tested.

The full system was built in the separate `software-data-diode-audit` Docker project.
The original full-project PostgreSQL volume, `.env`, and signing keys were not reset.
Existing standalone Phase 1 and Phase 2 deployments were verified in place.

## Confirmed Fixes

| Area | Defect and correction |
| --- | --- |
| Diode delivery | Transient network/408/429/5xx failures discarded dequeued messages. A bounded in-flight slot now retries the same signed message. Permanent client errors are dropped explicitly. |
| Gateway delivery | Information-policy handoff failures lost already-popped candidates. The pending signed envelope is now retained across transient failures without changing policy weights. |
| Replay state | Fog consumed replay state before downstream processing succeeded. Verification and completion are now separated, with serialized acceptance and an acknowledgement marker for an already-completed identical delivery. |
| Worker health | Unexpected egress exceptions could kill the worker while the API stayed green. The loop recovers, and readiness detects a stopped worker. |
| Queue accounting | In-flight messages were absent from occupancy, and rejected arrivals could be counted twice. Capacity reservation and drop accounting now include these cases. |
| Sequence ordering | Adaptive transport could reorder signed messages from one device, causing legitimate messages to fail strict replay checks. The live diode schedules among per-device queue heads. |
| Fog responsiveness | Database operations and audit verification could block async handlers. Processing, readiness, and rejection persistence now offload blocking work, with database connection/query timeouts. |
| Analytics retries | Retries regenerated anomaly/alert IDs and repeatedly updated detector history. A bounded per-message analysis cache reuses the same records during retries; in-memory repository behavior now matches idempotent database inserts. |
| Request validation | Added bounded streaming reads and typed-endpoint body limits; duplicate JSON keys, nonfinite values, and malformed structures are rejected. |
| Source isolation | Diode/Fog ingress now checks explicitly allowed Docker peers. Forwarded headers cannot spoof the client address on those services. Host ports default to loopback only. |
| File isolation | Edge, diode, and Fog previously shared writable access to all audit/state files. Each now mounts only its service subdirectory. A network-isolated initializer preserves legacy logs and gateway sequence state without overwriting migrated files. |
| Audit verification | A JSON scalar/array record could crash verification. It now reports the first invalid line. |
| Edge filtering | CPU, memory, telemetry type, attributes, and missing metric keys could be overlooked by change detection. These changes now remain visible; aggregates retain CPU/memory values. |
| Critical traffic | Generated critical events could be downgraded. Every virtual device marks critical status, and the classifier honors it. Invalid traffic-profile settings fail fast. |
| Metrics | Latency histories grew without bound; overall averages and p95 were incorrectly combined from priority summaries. Histories are bounded and aggregate latency is calculated from retained samples. |
| Monitoring | Stale Edge snapshots could remain ACTIVE; dashboard health was unconditional; active-alert queries could omit older unacknowledged alerts. Each is now checked independently. |
| Dashboard | A temporary monitoring outage erased the useful view. The last good snapshot remains visible with a stale warning. Refresh, pause, filters, view selection, timestamp columns, and score filtering are regression-tested. |
| Setup | Key generation could overwrite an existing identity. It now preserves and validates the pair, repairs only a missing public key, and refuses implicit private-key rotation. |
| Configuration | Nonfinite numeric settings and unusable anomaly/correlation rules are rejected. Database migrations stop on the first failed statement. |
| Tooling | Docker lookup supports per-user Windows installs; verification ports avoid the normal application ports; security cleanup is restricted to dedicated project names. The optional observability profile resolves its dependencies. |
| Experiments | Confidence intervals used the wrong table boundary for some degrees of freedom. Intervals now use conservative lower tabulated degrees of freedom. Nonfinite analysis values are excluded, and nonempty result directories cannot be overwritten by new trials. |
| Container logs | Python container stdout/stderr logs now rotate at 10 MB with three retained files. Audit-chain files remain separate and are not silently truncated. |

## Verification Evidence

| Verification | Result | Evidence |
| --- | --- | --- |
| Automated tests | **207 passed**, up from 131; one upstream Starlette/httpx deprecation warning | [JUnit XML](../audit-results/tests.xml) |
| Local statement/branch coverage | **65.2% combined**, including CLI tooling in the denominator | [HTML coverage](../audit-results/coverage-html/index.html), [JSON](../audit-results/coverage.json) |
| Full-stack Docker checks | **26 passed** | [Runtime results](../audit-results/runtime.json) |
| Standalone Phase 1 | **22 passed** | [Phase 1 results](../audit-results/phase1/verification.json) |
| Standalone Phase 2 | **47 passed** | [Phase 2 results](../audit-results/phase2/verification.json) |
| Local adversarial suite | **13 checks passed**: 11 attack scenarios plus two valid-traffic controls | [CSV](../audit-results/security/security-test-results.csv), [metrics](../audit-results/security/security-metrics.json) |
| Phase 7 experiments | **120 trials**: six workloads, four configurations, five trials each; ten figures and raw data generated; analysis regeneration passed | [Experiment report](../audit-results/phase7/experiment_summary.md) |
| Information-policy experiments | **245 trials**: seven workloads, seven configurations, five trials each | [Raw trials](../audit-results/information-policy/raw_trials.csv) |
| Python compilation | All application, shared, phase, experiment, and script directories passed | `python -m compileall` |
| Critical static checks | No E9/F63/F7/F82 findings | `python -m ruff check . --select E9,F63,F7,F82` |
| Compose validation | Full deployment built; standalone observability configuration valid | Docker Compose |

The runtime checks cover five active devices, persisted anomalies/alerts, both Prometheus
scrape sets, Grafana/dashboard readiness, network membership, blocked DNS/TCP reverse
paths, rejected Fog-to-diode ingress, per-service file visibility, migrated audit integrity,
and Fog/PostgreSQL outage recovery. Each injected recovery message was persisted once.
The final rejection-persistence thread change was additionally covered by an async
responsiveness test and the audit Fog Receiver was rebuilt and confirmed healthy.

The latest adversarial run sent 160 flood requests: 82 were rate-limited, the observed
queue never exceeded its configured capacity of 20, critical traffic progressed, and
none of 13 valid attempts was falsely rejected. These are controlled-run results, not
guarantees about arbitrary attacks or loads. No external attack targets were used.

## Module Coverage Boundaries

The unit suite exercises signing/hashing, replay checks, audit chains, queues, information
policy, filtering, priority assignment, device state, detectors/correlation, repository
contracts, all five generator types, transport failure paths, API errors, and Streamlit
controls. Real PostgreSQL/Prometheus/Grafana behavior and cross-container connectivity
are covered separately by Docker checks and are not included in Python unit coverage.
Helper CLI branches, exceptional shutdown paths, and several persistence error paths
remain incompletely covered; consult the HTML report for exact unexecuted lines.

## Remaining Limits

- The legacy full-stack queues, pending transport slots, analysis cache, and Fog replay
  detector are in memory. Dependency outages are retried, but process crashes/restarts
  can lose queued work or reset deduplication history. This is not durable exactly-once
  delivery. The standalone Phase 2 durable replay implementation is a separate path.
- Per-device transport ordering can delay a critical message behind an earlier message
  from that same device. Different device queue heads still receive priority scheduling.
- Isolation is software-enforced, not a physical data diode. Host/Docker-administrator
  compromise, transport responses, and covert channels are outside the demonstrated guarantee.
- Audit chains detect modifications relative to their current records, not malicious
  rewriting of the entire chain or truncation without an external trusted checkpoint.
  Long-term audit retention and storage-capacity planning remain deployment tasks.
- Generated counters describe the current Edge process; accepted counters are retained
  database totals, and snapshots arrive asynchronously. They need not match after restarts.
  Transport latency begins at the signed gateway envelope, not necessarily at device generation.
- Benchmark reports are discrete-event simulations. Their detection-delivery proxies and
  runner CPU measurements must not be presented as measured production detector accuracy
  or container CPU utilization.
- Streamlit interaction tests passed, but no browser automation connection was available.
  Visual/mobile screenshot validation and brightness-flicker observation were not performed.
- No long-duration soak, disk-full recovery, independent penetration test, or exhaustive
  dependency vulnerability audit was completed. No claim of 100% coverage or bug freedom is made.

## Upgrade and Run

The isolated audit dashboard is available at **http://127.0.0.1:18501** while
`software-data-diode-audit` is running. Grafana is at http://127.0.0.1:13000.
It uses a separate database, not the normal project's historical data.

Before first upgrading an existing full deployment, stop it so the one-time file migration
copies closed logs and a consistent sequence file. Keep its existing `.env`, signing keys,
and volumes. From the project directory, with Docker Desktop running:

```powershell
docker compose --profile full stop
docker compose --profile full up --build -d --wait --wait-timeout 180
docker compose --profile full ps
```

The normal dashboard defaults to http://127.0.0.1:8501. `runtime-state-init` and
`database-migrator` exiting successfully is expected. Do not use `down --volumes`,
delete the database volume, or regenerate credentials as a routine restart procedure.
The new layout requires Compose/Engine support for volume subpaths; the installed
Docker Desktop version was tested. [Docker's volume documentation](https://docs.docker.com/engine/storage/volumes/)
describes the prerequisite that subdirectories exist before mounting; the initializer
creates them before dependent services start.

To stop only the audit deployment while preserving its data:

```powershell
docker compose -p software-data-diode-audit --profile full stop
```

To rerun local tests, install `requirements-dev.txt`, then run
`python -m coverage run -m pytest -q` and `python -m coverage html`.
`python scripts/audit_runtime.py --outages` deliberately stops and restarts dependencies
only in the specifically named audit project; do not reinterpret it as a production health check.

# N2: Durable Observation Ledger

Copy the entire prompt below into the coding agent. Complete earlier phases first.

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N2: DURABLE OBSERVATION LEDGER

Prerequisite: N1 contracts and oracle pass their checks.

Goal: record each accepted observation before filtering, with bounded durable state and recovery.

1. Inspect the gateway's telemetry validation, registry, sequence persistence and asynchronous ingestion path. Add observation identity (ledger_epoch, device_id, ingress_sequence) before InformationEngine decisions. Preserve outgoing message UUIDs and transport sequences as a separate namespace.
2. Implement an Edge-only SQLite store with transactions and a serialized writer. Atomically record observation identity/canonical input, ingress window, per-condition fact updates, current disposition and evidence-reservation state. A request is accepted only after that transaction commits.
3. Keep the feature behind a disabled research-mode flag until integration. Reuse service initialization and non-root volume patterns. Fog must not mount or query the Edge ledger.
4. Bound input size, active windows, per-device state, retained records, database bytes and pending outbox bytes. Define compaction only for closed eligible material. Keep replay/epoch/identity protection meaningful after compaction. Disk full or unavailable storage cannot be acknowledged as durable acceptance.
5. Recover open windows, observation counters and reservation obligations before admitting new inputs. Persist an epoch across ordinary restarts. Define a controlled new-epoch/retirement process; a random UUID alone cannot reset replay protection. Do not reuse original project state in the research deployment.
6. Distinguish accepted observations from malformed or locally refused inputs. Coverage is accepted-gateway-ingress coverage, not generated-message completeness. A missing relevant metric is unresolved condition evidence.
7. Use gateway ingress time for contract membership. Clock discontinuities, downtime and uncertain recovery are recorded as limitations; never synthesize normal historical windows.
8. Exercise concurrent devices, transaction rollback, interrupted admission, restart before/after commit, duplicate local retries, bounded retention and storage exhaustion. Use fault injection at meaningful transaction boundaries rather than tests that only mirror setter methods.

Acceptance: every acknowledged observation appears exactly once in the durable accepted scope, facts recover consistently, and state remains bounded. Any admission that cannot be accounted for is refused or explicitly limited, never silently accepted.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N2.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

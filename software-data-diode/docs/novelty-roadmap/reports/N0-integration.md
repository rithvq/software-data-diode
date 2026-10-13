# N0 integration checklist and baseline modes

Status: planned changes only, frozen 2026-10-13. No coverage Compose override or runtime flag has been implemented.

## Comparator definitions

Every new coverage comparator uses N0-contract-v1, the same original ingress trace, registered opportunities and deadlines. Existing legacy metrics are retained under their original interpretation.

| ID | Mode | Required behavior |
|---|---|---|
| B0 | Unfiltered FIFO + gap-aware monitoring | No semantic reduction; tail-drop at finite capacity. Original ingress references on retained raw data; missing negative evidence remains unknown. |
| B1 | Current adaptive/legacy behavior | Preserve both legacy Phase 3 mode and current InformationEngine mode as documented references. Legacy alerts are not exact v1 verdicts and cannot be presented as the same clock/window semantics without a declared adapter. |
| B2 | Signed heartbeat and sequence-gap monitoring | Send bounded counts/continuity/health metadata, without per-condition truth summaries. Heartbeat liveness alone does not certify a complete negative result. |
| B3 | Simple signed predicate summaries | Maintain the same pre-reduction facts and scope as RCCD, with a fixed periodic service/reserved share. No incremental evidence reservation coupled to individual reduction admissions. This is a strong baseline, not an intentionally starved metadata queue. |
| P | Coupled RCCD | Admission/irreversible reduction accounts for durable facts, evidence storage and future forward-byte obligations together. |
| C | Always UNKNOWN | Honest zero-definite-answer control. It cannot win by reporting zero wrong answers alone. |

B3 must include a properly sized fixed metadata reservation as well as an unreserved variant where useful. Do not compare the proposal only against a weak FIFO metadata queue. If fixed reservations and simple facts perform equivalently, report that result and revise the claimed contribution.

All byte accounting includes raw metadata, heartbeat, signed facts, framing/parts, configured repeats and actual wire overhead where measured. Match observation scope and compare known answers, unknown rate and wrong definite answers together.

The existing information runner supports FIFO, priority, utility-only, filtering-only, no-prediction, full policy and density-under-pressure comparisons. Those simulations remain reproducible; they do not implement any of B2/B3/P's new signed-coverage behavior.

## Implementation ownership

| Phase | Current file/component | Required future change/check |
|---|---|---|
| N1 | shared/coverage/ (new) | Restricted contracts, explicit metric paths, canonical hashes, window clock and independent oracle |
| N1 | config/rule_coverage.json (new) | Resolved versioned contracts with actual generator metric names |
| N2 | edge-gateway/app/main.py | Transactional pre-policy ingress, original identities and durable membership |
| N2 | shared/edge/state.py | Keep outgoing sequence persistence distinct from ingress identity |
| N2 | phase2/state.py | Reference existing SQLite transaction/recovery patterns; do not import its strict sequence semantics unchanged |
| N2 | Edge-only named volume (new) | UID-compatible SQLite location; no shared Edge state mount into Fog |
| N3 | shared/security/crypto.py | Reuse canonical/hash/signature primitives with separate artifact domains |
| N3 | shared/models/telemetry.py | Compatible signed ingress references; separate artifact schema for RCC |
| N3 | shared/security/audit.py | Evidence/obligation audit events without equating audit continuity to query completeness |
| N4 | shared/traffic/information.py | Focused reduction/admission hook; preserve all existing baseline modes |
| N4 | gateway policy worker | Atomic disposition/obligation changes and bounded durable outbox |
| N4 | shared/traffic/scheduling.py | Byte-accounted conditional service; no unrestricted receiver inputs |
| N5 | data-diode/app/main.py | Selectable passive UDP forwarding; research-mode readiness and metrics path changes |
| N5 | fog-receiver/app/main.py | Bounded UDP intake/parts; no response to sender |
| N5-N6 | shared/security/replay.py | Separate durable reorder-aware research verifier; keep existing HTTP behavior |
| N5 | docker-compose.coverage.yml (new) | Minimal override; no fixed subnet; scoped volumes, flags and loopback ports |
| N5 | observability control network | Remove Grafana-to-Edge-Prometheus request path in the new deployment |
| N6 | shared/persistence/repository.py | Evidence identities/facts/verifier outcomes with transactional replay acceptance |
| N6 | database/migrations/ (new numbered files) | Additive schema changes; preserve accepted telemetry/history |
| N7 | shared/analytics/correlation.py | New v1 path; never silently change legacy 60/90-second receive-time rules |
| N7 | fog-analytics/app/main.py and alert-engine | Idempotent scoped verdict/incident/visibility records |
| N8 | monitoring-api/app/store.py and main.py | Bounded queries from Fog tables only |
| N8 | dashboard/app.py | Evidence view, stable fragment refresh and last-good snapshot handling |
| N9 | security-test-client/app/main.py | Isolated evidence/recovery/flood/replay validation |
| N10 | experiments/runners/ and analysis/ | Paired faults, independent oracle and matched total byte budgets |
| N11 | scripts/docker_support.py and demo.py | Local start/status/demo/stop/restart support and accurate absence-of-service messages |

## Required boundaries before implementation

- Current scope uses Pydantic-normalized gateway observations, not bit-identical source JSON or guaranteed sensor truth.
- Current root/measurement extraction precedence differs across policy and analytics. The contract must name exact paths.
- Current gateway accepts research messages into memory; audit appends do not make the pending candidate durable.
- Current transport retry outcomes affect queue progression even though they do not alter InformationEngine weights. The new no-application-response mode must replace that progression.
- Current readiness follows Gateway -> Diode -> Fog -> internal dependencies. Research sender readiness cannot rely on Fog responses.
- Current Grafana has a proxy datasource to Edge Prometheus across observability-control-network. Streamlit's Fog-only reads do not eliminate this auxiliary path.
- Shared host ports, Docker routing and privileged host access are outside a physical one-way guarantee.
- Current full-stack replay and analysis caches are in memory. Standalone phase2's SQLite state is a different deployment, not proof of full-stack durability.
- A fixed-size signed summary may already be sufficient for v1 predicates. The coupled mechanism must earn any extra complexity against B3.

## Local deployment plan

Project name: software-data-diode-coverage. Base: docker-compose.yml. Future override: docker-compose.coverage.yml. Reuse core/full profiles rather than creating a separate implementation of each service.

Planned flags:

| Flag | Default for existing behavior | Research selection |
|---|---|---|
| RULE_COVERAGE_ENABLED (new) | false | true |
| DIODE_FORWARD_TRANSPORT (new) | http | udp |
| INFORMATION_POLICY_ENABLED (existing) | preserve existing setting | true, with the new semantic/admission hook |

These are planned names; setting the first two in today's deployment has no implemented effect.

Use unique project-scoped network and volume names; no external/global volume names that alias the main project. Bind operator-provisioned contract files and approved key files read-only. Use a distinct ledger epoch and separate Edge/Fog state. Never regenerate primary keys or passwords during research setup.

Proposed local port set, subject to availability checks at N5:

| Interface | Host binding |
|---|---|
| Edge Gateway demonstration | 127.0.0.1:38000 |
| Streamlit | 127.0.0.1:38501 |
| Fog Prometheus | 127.0.0.1:39090 |
| Optional Edge-local Prometheus | 127.0.0.1:39091 |
| Fog Grafana | 127.0.0.1:33000 |

Host observations are experiment instrumentation, not inputs to the scheduling policy. Do not publish the diode/Fog UDP boundary on the host. Docker allocates subnets automatically.

In research mode Grafana reads Fog-resident copies of forward-exported Edge metrics. If Edge Prometheus is retained, keep it Edge-local and remove its shared control-network membership/datasource from Fog Grafana. Do not claim no reverse application path while preserving the current cross-zone proxy datasource.

Before deployment, validate merged Compose ports, mounts and profiles; an override can accidentally append ports/networks instead of replacing them. Capture effective memberships and host bindings rather than trusting YAML intent alone.

## Prerequisites and completion gates

N1: implement pure contracts and an independent oracle with no live path changes.
N2: durable acceptance/recovery tests before any preservation claim.
N3-N4: serialized evidence sizes and configuration feasibility before coupling admissions.
N5: observed forward-only application behavior and isolation; report UDP/host limitations.
N6-N7: durable verification and correct scope-bound verdicts.
N9: fix all in-scope wrong definite answers before performance evaluation.
N10: retain negative findings and the fixed-reservation B3 comparison.

N0 does not perform startup, outage/restart tests, live reverse-path probes, database migrations, UDP deployment or new experiments.

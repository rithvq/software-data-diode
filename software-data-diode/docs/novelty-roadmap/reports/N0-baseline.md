# N0 current implementation inventory

Observed source and test baseline: 2026-10-13.
This inventories the current system; RCCD runtime work remains planned.

## Runtime and data flow

The full stack contains five Edge devices, Edge Gateway, Data Diode, Fog Receiver, Event Processor, Analytics, Alert Engine, PostgreSQL, Monitoring API, Streamlit, split Prometheus and Grafana. Two one-shot initialization services prepare state and migrations.

HTTP carries selected signed payloads and forward observability snapshots. A separate standalone phase1/phase2 track has one device and three logical networks.

| Component | Current implementation | Limit relevant to RCCD |
|---|---|---|
| edge-device/app/main.py | Five independent environment-selected telemetry types; seeded profiles and normal/burst/overload/critical traffic | Full-stack inputs are unsigned and lack pre-filter durable observation identity |
| edge-gateway/app/main.py | Freshness/schema checks, priority, legacy filter or InformationEngine; outgoing signing/sequence after selection; retry retains a signed identity | Policy candidate queue and pending envelope are in memory |
| shared/traffic/information.py | Local estimator, predictor, eight utility terms, six actions, bounded queue, protected events and aging | No rule contract, original-observation ledger or evidence-byte reservation |
| shared/traffic/filtering.py | Legacy significance/dedup/sample/aggregate path | Reduction does not establish original-input predicate completeness |
| shared/edge/state.py | Per-device health/rate/filter/priority counters and optional durable outgoing sequence file | These are selected-message sequences, not pre-policy observation coverage |
| shared/models/telemetry.py | Strict payload/envelope models, aggregates with means/extrema/source IDs/windows | No independent RCC artifact, contract hash or canonical ingress-window identity |
| shared/security/crypto.py | Sorted compact canonical JSON, finite-number rejection, SHA-256, Ed25519 | Signatures authenticate the signing gateway, not correctness of omitted inputs |
| shared/http.py | Bounded bodies, strict JSON and peer allowlists | Boundary controls are software controls; they do not provide physical unidirectionality |
| shared/security/replay.py | In-memory UUID TTL and highest-sequence/latest-time checks | Legitimate UDP reordering is rejected; state does not survive full-stack restart |
| shared/security/audit.py | Append-only hash chain and verification utility | Full input coverage is not proved; wholesale history rewrite needs an external reference to detect |
| data-diode/app/main.py | Bounded FIFO/adaptive transport, rate limits, signed-message forwarding and response-based retry | Data forwarding, metrics export and readiness consume Fog HTTP responses |
| fog-receiver/app/main.py | Size/schema/hash/signature/freshness/replay validation; serialized downstream acceptance | Receives selected payloads, not a certified population of original observations |
| event-processor/app/main.py | PostgreSQL persistence and forwarding to analytics; blocking I/O offloaded | Full-stack pending downstream work is not a durable evidence intake journal |
| shared/analytics/detection.py | Threshold, moving-average and z-score detectors over received payload values | An aggregate's mean is not the original sequence; no exact missing-data contract |
| shared/analytics/correlation.py | Configured conditions over Fog received_at windows with cooldown | Current 60/90-second rolling behavior differs from proposed 10-second ingress windows |
| fog-analytics/app/main.py | Analysis retry cache and persistence/alert integration | Cache is bounded but in memory; no coverage-dependent three-valued verdict |
| alert-engine/app/main.py | Severity/evidence records, database-backed alert creation | No RCC window/verdict identity or evidence-visibility result |
| shared/persistence/repository.py | In-memory/testing and PostgreSQL implementations for current records | No RCC, per-condition coverage, reservation or durable research replay tables |
| monitoring-api/app/main.py and store.py | Fog database snapshots and Fog service health; audit verification cached/offloaded | Current snapshots mix lifetime database totals with process/session counters |
| dashboard/app.py | Four views, sidebar cadence/toggle/manual refresh, snapshot download, filters and last-good snapshot | No Evidence Coverage view; rendering can still need live browser validation |
| shared/observability/ | JSON logs and Prometheus-compatible service metrics | Existing counters do not measure complete rule-preservation evidence costs |
| security-test-client/app/main.py | Isolated target validation, tampering/replay/flood/reverse-path/audit scenarios and CSV/JSON | These vectors do not yet test RCC contracts or no-ACK UDP recovery |
| phase1/interfaces.py and pipeline | Replaceable policy/scheduler protocols and transport instrumentation | Pass-through baseline; no evidence contracts |
| phase2/state.py and pipeline | SQLite WAL/FULL transaction state, bounded pending outbox and restart-aware security | Standalone, strict ordered transport; does not add durability to full stack |
| scripts/ | Setup, config, keys, demos, network/audit/security verification and Docker locator | Several existing runners start/stop containers; they were not used for read-only N0 capture |

The baseline manifest inventories HTTP route names/methods/line numbers directly from AST, along with all Compose service profiles and configured networks.

## Dashboard refresh baseline

The current code uses a sidebar toggle and segmented cadence control, then st.fragment(run_every=selected_cadence). Manual refresh calls st.rerun(). API requests time out after four seconds. Session state retains last_good_snapshot during a failure.

The existing CSS disables opacity changes for stale Streamlit element containers. Existing AppTest checks cover selection, pause and missing snapshots. N0 does not certify mobile rendering, brightness stability or real timer cadence in a live browser.

## Database schema baseline

001_phase4_schema.sql creates accepted_telemetry, rejected_messages, security_events, anomalies, alerts, experiment_metadata and performance_metrics, plus device/alert summary views.

002_phase5_observability.sql adds observability_snapshots, a latest-snapshot view and alert acknowledgement compatibility. There is no coverage migration. N0 ran no SQL against existing databases.

## Experiment baseline

| Runner | Actual measurement | Scope limit |
|---|---|---|
| experiments/runners/benchmark.py with run_phase7.py | Seeded synthetic arrivals, filtering/FIFO/adaptive simulations, queue/latency/drop/byte estimates, runner CPU/tracemalloc and synthetic detection tags | Not live Docker/wire throughput or independent rule-coverage truth |
| experiments/runners/information_benchmark.py | Uses deployed InformationEngine in discrete events; seven strategies/seven workloads with at least five trials; retains traces/decisions/config fingerprints | Representation of aggregated samples is not exact raw recovery; service capacity and bytes are modeled |

Existing reports and retained historical CSV/graphs remain untouched. No historical measurements are relabeled as RCCD results.

The earlier `docs/phase2_completion_report.md` records 131 local tests and 47 live checks for the separate phase2 deployment. `docs/codebase_audit.md` records the September 23 audit's 207 local tests, live full-stack/security checks and simulated trials. These are historical reports, not checks rerun in N0. Their stated strict-order replay, in-memory full-stack state, selected-envelope latency and modeled benchmark limits agree with the inspected source. N0 does not promote the historical live results to a current deployment certification.

## Test inventory

The JUnit baseline retains all 207 collected node identities, including parameterized cases. Coverage areas include:

- policy, filtering, priorities, scheduler, per-device state and signed dispatch ordering;
- hashes/signatures, request validation, freshness/replay, audit chains and key preservation;
- Fog threshold/correlation logic, persistence abstraction and monitoring-store behavior;
- service retries, queue bounds, dependency readiness and async responsiveness;
- dashboard controls/fallback snapshots;
- standalone phase1 instrumentation and phase2 durable-state/security behavior;
- experiment determinism/repeated-trial statistics and packaging/Compose assertions.

Local tests use mocks/in-process clients and temporary stores. They are not a live PostgreSQL or Docker security certification. Seven new tests validate the N0 capture utility's secret exclusions, stable fingerprints, field sanitization, read-only command set and truthful JUnit result accounting.

## Observed deployment versus configured deployment

Docker Engine is reachable with permitted read access. Container state was observed as stopped for the main, audit, standalone phase1 and standalone phase2 projects. Refer to the timestamped manifest for exact counts and versions; the collection is sequential, not an atomic snapshot.

Stopped-container configured attachments agree with the main separation: gateway joins Edge/diode/host-Edge; diode joins diode/Fog-ingress; Fog Receiver joins Fog-ingress/Fog-services; Streamlit joins Fog-services/host-Fog. None of those Fog application services is configured on the Edge device network.

Network inspection found no active project endpoints. This does not prove live reverse-path rejection or service health. Stored previous health data for a stopped container is not current health.

The observability-control network connects both Prometheus services and Grafana, whose Edge datasource uses proxy access. That auxiliary request path must be accounted for in the future research topology. Dynamic subnet allocation is used in the current Compose source; existing leftover networks can still have historical fixed address ranges.

## Implemented versus planned

| Capability | N0 status |
|---|---|
| Current signed HTTP pipeline, filtering/scheduling, Fog analytics/UI | Present in code; local tests pass; containers stopped |
| N0 repeatable source/config/dependency/test/Docker capture | Implemented and tested |
| Frozen v1 scope, comparator modes and independent oracle definition | Documented specification only |
| Durable full-stack original observation ledger | Planned N2 |
| RCC schema/signing/parts | Planned N3 |
| Coupled evidence-byte reservation | Planned N4 |
| UDP no-application-response mode | Planned N5 |
| Durable Fog coverage verifier | Planned N6 |
| Three-valued coverage correlation | Planned N7 |
| Evidence dashboard and new measurements | Planned N8-N10 |
| Patent novelty/eligibility/FTO | Unestablished; professional assessment not performed |

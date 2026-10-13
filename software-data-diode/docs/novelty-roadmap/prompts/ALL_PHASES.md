# RCCD phase-by-phase build prompts

Prepared 2026-10-13. All phases are planned; this file does not certify implementation.

Use these in order, one complete fenced prompt per agent turn. Each prompt reads the same repository specification and includes its own scope and completion requirements. Do not paste all phases at once.

## N0: Baseline and Specification Freeze

Individual file: [00-baseline-and-specification.md](00-baseline-and-specification.md).

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N0: BASELINE AND SPECIFICATION FREEZE

Goal: record the working starting point and freeze a technically precise research scope before modifying runtime behavior.

1. Inspect README.md, docs/feedback_free_design.md, docs/research_phases.md, shared/traffic/information.py, existing schemas/security/replay, all service entry points, database migrations, Compose files, dashboard refresh code and both experiment runners. Record what actually exists and which claims are only planned.
2. Inventory tests. Run configuration validation and relevant local tests using the existing .venv Python. When Docker is available, collect service health and network memberships using read-only commands first. Do not recreate the main deployment merely to obtain a baseline.
3. Create a baseline manifest with source/config fingerprints, dependency versions and test evidence. Redact secrets. Record known limits: outgoing sequences are allocated after reduction, selected payloads do not establish original-input completeness, existing replay handling is not suitable unchanged for UDP reordering, and current HTTP health/observability paths cross the future research boundary.
4. Review the sources in prior-art.md. Search full claims/publications for the narrow coupling of rule-preserving reduction and advance evidence-byte reservation. Add links, dates, exact overlap and remaining uncertainty. Do not turn an unsuccessful search into a novelty claim or assume a public specification is a granted patent.
5. Freeze v1 contracts: accepted-gateway-ingress scope; aligned 10-second windows; EXISTS and COUNT_GE numeric inequalities; AND/OR composition; preprovisioned contract hashes; no continuous-time or arbitrary temporal predicates.
6. Define baseline modes and the independent raw-trace oracle. Write an integration checklist that maps proposed changes to current files. Document all unsafe assumptions before implementation.
7. Plan one isolated software-data-diode-coverage Compose project with separate state, loopback host ports and a config flag. Do not deploy it yet.
8. State a patent/research stop-go assessment. If close prior art undermines the distinction, narrow the claim or mark it unestablished; continue useful specification work without making legal promises.

Acceptance: the starting behavior, scope, evidence obligations, strong comparison methods and remaining novelty risks are reviewable in writing. No runtime feature is claimed implemented by this phase.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N0.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

## N1: Rule Contracts and Exact Semantics

Individual file: [01-rule-contracts.md](01-rule-contracts.md).

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N1: RULE CONTRACTS AND EXACT SEMANTICS

Prerequisite: N0 has recorded a baseline and scoped v1 semantics.

Goal: implement the pure rule-contract layer and an independent oracle, without changing live telemetry behavior yet.

1. Add a focused shared/coverage package using the project's typed-model conventions. Define immutable RuleContract, AtomicCondition, WindowIdentity, ConditionFacts and RuleVerdict models, including explicit observation scope, units, numeric interpretation, window time basis, minimum sample requirements and bounded device/rule cardinality.
2. Implement canonical contract hashing with the existing cryptographic serialization helpers where compatible. All fields that affect meaning must be hashed. Reject nonfinite values, duplicate/ambiguous identifiers, unsupported operators and arbitrary executable expressions. Make numeric boundary behavior deterministic; test values immediately around thresholds.
3. Support EXISTS and COUNT_GE for >, >=, <, <=, plus same-window AND/OR. Implement the strong Kleene truth tables from design.md. Separate rule truth from artifact verification and general device health. A FALSE AND-result is not globally complete coverage.
4. Define UTC-aligned ingress windows and monotonic closure scheduling through an injected clock interface. Define startup, boundary inclusivity, clock jump and interrupted-window behavior. Do not infer simultaneous physical events from membership in one window.
5. Add config/rule_coverage.json with a small set of environmental, industrial and CPU/network/failed-login rules. Label thresholds as synthetic demonstration settings. Reuse actual metric names after inspecting device configurations.
6. Implement an independent full-ingress-trace oracle for tests and experiments. It must not call the capsule evaluator or filter-policy methods; avoid comparing an implementation with itself.
7. Add meaningful tests for hashing, configuration limits, all truth-table cells, zero/missing observations, missing metrics, COUNT_GE bounds, device scoping and window boundaries. Exhaustively compare small finite traces with the independent oracle.

Acceptance: contracts have deterministic identities; unsupported semantics fail visibly; pure evaluation produces correct definite results and justified UNKNOWN cases. The existing full deployment and tests continue to work.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N1.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

## N2: Durable Observation Ledger

Individual file: [02-durable-ingress-ledger.md](02-durable-ingress-ledger.md).

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

## N3: Signed Rule Coverage Capsules

Individual file: [03-signed-coverage-capsules.md](03-signed-coverage-capsules.md).

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N3: SIGNED RULE COVERAGE CAPSULES

Prerequisite: N2 durable admission and recovery are verified.

Goal: create bounded, self-contained evidence for original accepted observations, using existing cryptographic primitives.

1. Introduce a separate versioned RCC artifact schema. Do not force evidence into a fake ordinary telemetry payload. Bind gateway/key identity, ledger epoch, immutable capsule identity, contract hash, device/window scope, ingress range, accepted count, time basis, closure reason, facts, limitations, reduction accounting and predecessor digest.
2. Accumulate matching/nonmatching/unresolved counts before policy transformation. Verify their sum equals the declared accepted count for each atomic condition. Include only the minimal sufficient facts needed by v1 predicates and bounded witness references. Do not derive threshold facts from an aggregate mean.
3. Keep semantic coverage separate from raw selection, raw dispatch, queue overflow and confirmed receipt. A committed exact predicate fact may represent a raw sample later dropped locally. It does not prove raw delivery.
4. Use canonical serialization, SHA-256 and Ed25519 with domain separation between contracts, telemetry and evidence. Sign every field used to determine scope, identity or meaning. Repeated artifacts must reuse identical signed bytes.
5. Provide a sender input commitment for offline audit, with explicitly named construction and canonical vectors. State that Fog cannot independently recompute withheld inputs from a digest alone. Online assurance is AUTHENTICATED_SUMMARY under a trusted gateway; offline raw recomputation is a distinct check.
6. Seal each window independently. Missing a predecessor marks chain continuity incomplete but does not automatically invalidate an independently usable later window. Detect two different signed bodies with the same immutable scope identity.
7. Define no-input, missing-metric, recovery, time-discontinuity and contract-transition artifacts. An empty capsule or heartbeat cannot certify no event when the contract requires observations.
8. Enforce hard serialization/record/list bounds. Specify bounded signed transport parts if a capsule does not fit the future 1,200-byte datagram limit.
9. Test canonical vectors, every meaningful field mutation, wrong keys, count contradictions, identity forks, recovery closures, redelivery and offline recomputation.

Acceptance: artifacts authenticate their exact declared scope, remain bounded, and clearly distinguish authenticated assertions from independently recomputed facts.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N3.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

## N4: Coupled Reduction and Evidence Admission

Individual file: [04-semantic-reduction-and-admission.md](04-semantic-reduction-and-admission.md).

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N4: COUPLED REDUCTION AND EVIDENCE ADMISSION

Prerequisite: N3 capsules are correct and their serialization costs are known.

Goal: implement the main proposed technical factor: irreversible telemetry reduction is coupled to evidence storage and forward-byte reservation.

1. Inspect shared/traffic/information.py and gateway queue integration. Add a small hook around candidate actions rather than a second unrelated decision engine. Preserve current InformationEngine behavior as a named baseline.
2. Before SAMPLE, AGGREGATE, SUPERSEDE or DROP changes a routine candidate, ensure its original condition facts are durably maintained and reserve the bounded cost of the eventual evidence. Reject or explicitly limit a decision whose evidence obligation cannot be supported. Do not promise an exact full raw reconstruction from predicate facts.
3. Make reservations hard admission constraints, not just score terms. Persist obligations and reconcile worst-case reserved bytes against actual serialized capsules at closure. Include signatures, headers, bounded parts and configured repeats in the total.
4. Implement a bounded durable outbox for raw work and evidence. Use an explicit byte-based service policy for evidence, protected events and routine data. Start with a configurable 10% evidence share for experiments, allow idle borrowing with a bounded later service rule, and avoid starving critical events or evidence under admitted load.
5. Keep scheduler inputs Edge-local: original observations, local queue/storage state, configured link capacity and local clocks. No Fog replies, receiver metrics or host-harness feedback enter scoring, reservation or reduction decisions.
6. Validate rule count, closure frequency, evidence-frame bounds and configured capacity at startup. Impossible evidence budgets fail clearly or produce an explicitly limited operating mode; evidence is never treated as free.
7. Handle finite-capacity overload honestly. Persist raw evictions and unsupported facts. No unlimited critical-delivery or evidence-delivery guarantee is allowed.
8. Test matched-byte budgets, underfunded contracts, reservation rollback/recovery, every reduction action, critical-only saturation, mixed floods, evidence closure latency and bounded storage. Compare the coupled path with fixed signed summaries without reservation using small deterministic traces.

Acceptance: reduction decisions and evidence obligations share an atomic accounting boundary; total scheduled bytes obey the configured model; protected traffic and evidence behavior have tested conditional service bounds.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N4.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

## N5: Forward-Only Research Transport

Individual file: [05-forward-only-local-transport.md](05-forward-only-local-transport.md).

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N5: FORWARD-ONLY RESEARCH TRANSPORT

Prerequisite: N4 produces immutable evidence/raw outbox work with valid budgets.

Goal: deploy a local research transport that can lose/reorder traffic without any receiver application feedback.

1. Add a selectable transport interface. Keep the existing HTTP mode for baseline and rollback. In RCCD mode, Data Diode sends UDP datagrams to Fog Receiver, with no ACK/NACK or receiver-response socket used by the sender.
2. Disable diode-to-Fog HTTP readiness polls, message-response retries and request/response observability export in this mode. Replace required Edge state export with bounded signed forward records included in the traffic budget. Internal Edge and internal Fog HTTP calls remain allowed.
3. Keep Data Diode a passive bounded forwarder. Gateway policy inputs must not include Fog readiness, status codes, processing latency, queue state or collector observations. Local send() success is recorded as attempted dispatch, not receipt.
4. Enforce 1,200-byte datagram payloads including signed envelope fields. Implement bounded authenticated parts when needed: artifact identity, part index/count, whole-body digest and signature binding. Bound part count, total bytes, partial assemblies and timeout. Missing parts must not trigger a reverse request.
5. Support optional fixed evidence repeats with identical signed bytes and local schedule. Charge all repeat/part bytes. Default choices must be explicit and experimentally ablatable.
6. Add a separate durable reorder-aware replay path for research envelopes. Do not weaken or silently reuse the existing highest-sequence-only verifier. Define bounded history, stale windows, retired epochs and duplicate identities.
7. Create docker-compose.coverage.yml as a minimal override of current services, with an isolated software-data-diode-coverage project, research mode flags, Edge-only ledger volume, separate state and loopback dashboard ports. Avoid fixed subnets and new infrastructure services.
8. Test drop, reorder, duplicate and delayed datagrams with a seeded local forward fault adapter. Verify Fog cannot resolve/connect to Edge application services and record actual memberships. Inspect cross-boundary packet captures or equivalent instrumentation to show the tested mode sends no application replies; distinguish that result from physical or privileged-host enforcement.
9. Add startup/config checks and correct local liveness/readiness semantics. Fog unavailability must expose stale coverage, not block an ACK-free sender waiting for readiness.

Acceptance: the research path runs locally, has bounded state, does not require receiver replies, and accurately labels attempts, receipt and software-isolation limits.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N5.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

## N6: Fog Verification and Persistence

Individual file: [06-fog-verification-and-storage.md](06-fog-verification-and-storage.md).

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N6: FOG VERIFICATION AND PERSISTENCE

Prerequisite: N5 has a working bounded transport and documented frame semantics.

Goal: accept evidence durably and expose what was actually verified.

1. Add Fog-side evidence verification using provisioned trusted public keys and contract files. Verify version/kind, canonical bytes, signature, contract hash, device/window/epoch scope, count identities, metric compatibility, bounds, part completion and freshness.
2. Produce a typed verification record with scope, verifier version, assurance level, continuity status, limitations and reason codes. A valid signature is not a proof that the gateway's hidden observations are true.
3. Handle exact duplicate signed artifacts idempotently. Treat differing valid bodies for one immutable scope identity as conflict. Quarantine/reassess affected scopes rather than silently accepting the first. Invalid unrelated injected artifacts must not overwrite valid evidence.
4. Treat independently signed later-window facts separately from predecessor continuity. A missing earlier capsule creates a historical gap, not automatic loss of all later independent facts.
5. Add additive numbered migrations under database/migrations for capsules/parts, verified scope facts, verification outcomes, rule verdicts, conflicts and related performance metrics. Reuse shared/persistence/repository.py and existing migration initialization patterns. Preserve existing rows and credentials.
6. Commit identity/replay acceptance with accepted evidence transactionally. Make downstream publication idempotent and recoverable. Keep durable epoch/window rules after bounded replay-cache eviction; storage expiry cannot silently make old artifacts fresh.
7. Inspect Fog intake during PostgreSQL outages. Use a bounded Fog-local durable spool only if needed; expose overflow/limits. Never acknowledge durable receipt when neither spool nor database committed. Do not add a reverse delivery response.
8. Keep blocking database/storage calls off the async event loop using the repo's existing approach. Validate readiness, shutdown, recovery and contract transitions.
9. Test actual PostgreSQL migrations and repository behavior in the isolated research project, plus transaction failure, duplicate receive, signature/schema rejection, reassembly expiry, replay after restart, identity conflict and database recovery.

Acceptance: verified artifact identities and facts survive restart, duplicate processing does not duplicate alerts, and the database records exactly which scope/assurance was checked.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N6.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

## N7: Coverage-Aware Rules and Alerts

Individual file: [07-coverage-aware-analytics.md](07-coverage-aware-analytics.md).

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N7: COVERAGE-AWARE RULES AND ALERTS

Prerequisite: N6 persists verified facts and their limitations.

Goal: make Fog monitoring decisions use sufficient evidence instead of inferring completeness from silence.

1. Integrate the N1 rule evaluator with persisted original witnesses and N6 RCC facts. Keep the legacy anomaly/correlation path as a named baseline. Do not feed summary means into raw-sample detectors and then label their outputs exact rule-preservation results.
2. Evaluate EXISTS and COUNT_GE using sound lower/upper bounds. TRUE may be supported by an authenticated matching fact or valid original witness. FALSE needs sufficient scoped negative/count evidence and declared observation requirements. Missing evidence stays UNKNOWN.
3. Compose same-window conditions with the documented Kleene AND/OR rules. Keep overall observation coverage independent from the rule result. In particular, FALSE for one AND-condition does not certify every other device observed.
4. Add the demonstrated CPU/network/failed-login correlation with inspected real metric names and synthetic thresholds. Explain the quantifier: each condition has a match in the same ingress window, not necessarily a simultaneous physical occurrence.
5. Persist rule-window verdicts with contract hash, scope, supporting artifact IDs, cause/reason and versioned revision history. UNKNOWN may become definite after late valid evidence; a conflict must be visible and reassess affected decisions.
6. Integrate TRUE incident results with Alert Engine. Add visibility alerts for missing/expired/unsupported evidence that identify degraded observation rather than inventing an attack. Keep decision status separate from INFO/WARNING/HIGH/CRITICAL severity.
7. Implement deterministic rule/window identity and restart-safe alert idempotency/cooldown. Neither duplicate capsules nor repeated processing may produce repeated incidents.
8. Test positive evidence with partial coverage, complete negative evidence, missing devices, incomplete counts, differing contracts, late parts, boundary windows, forks, restart and no-input windows. Compare every definite answer with the independent original-ingress oracle.

Acceptance: no tested definite answer contradicts the scoped oracle, UNKNOWN has a clear explanation, and alert storage preserves evidence references and independent coverage health.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N7.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

## N8: Evidence Coverage Dashboard

Individual file: [08-evidence-dashboard.md](08-evidence-dashboard.md).

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N8: EVIDENCE COVERAGE DASHBOARD

Prerequisite: N7 provides stable Fog verification/verdict APIs and data.

Goal: make the unique mechanism visible and usable in the current Streamlit application.

1. Extend Monitoring API from Fog persistence only. Add bounded, paginated queries for rule/window verdicts, devices, coverage freshness, capsule details and evidence-byte totals. Never query Edge services or mount the Edge ledger.
2. Add an Evidence Coverage view to dashboard/app.py using existing UI patterns. Show device/rule/time filters, TRUE/FALSE/UNKNOWN with text and accessible color, original versus raw-selected/represented observations, missing/partial/conflicting evidence and declared scope.
3. Make it possible to select a rule window and inspect the exact supporting capsules/witnesses, contract hash, reason, assurance level and continuity. Provide JSON/CSV downloads and a snapshot. Display sender-authenticated summaries distinctly from offline raw recomputation.
4. Add evidence bytes, evidence fraction of total forward bytes, definite-decision yield and UNKNOWN rate. Distinguish counters from the current process/session and totals persisted historically. Do not compare Generated and Accepted counters with different scopes.
5. Keep FALSE labeled as no matching result in its covered observation scope, not globally safe. Show active device coverage separately.
6. Preserve stable refresh using the actual current fragment/timer/session-state architecture. Refresh-interval changes must take effect, pause must work, manual refresh must work and last good data should remain readable during an API timeout. Eliminate full-page dimming/rerun loops.
7. Use high contrast, compact headings, fixed dimensions, responsive table/chart widths and familiar controls. Reuse the current framework; do not rebuild in React or add a marketing page.
8. Instrument bounded-cardinality Prometheus metrics for evidence byte cost, pending obligations, verification failures and unknown/definite verdicts. Extend existing Grafana configuration only where it helps inspect this mechanism.
9. Use Streamlit AppTest/API checks for controls and screenshot/browser checks across desktop/mobile where available. Test refresh selection, pause, filtering, downloads, timeout and empty/large results. Report visual checks not executed.

Acceptance: a user can see why a decision is definite or unknown and inspect its evidence without losing UI state during refresh. All runtime reads remain Fog-side.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N8.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

## N9: Security and Scoped Correctness Validation

Individual file: [09-adversarial-and-invariant-tests.md](09-adversarial-and-invariant-tests.md).

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N9: SECURITY AND SCOPED CORRECTNESS VALIDATION

Prerequisite: N8 is usable and earlier correctness tests pass.

Goal: test the mechanism against controlled local adversarial traffic and failure patterns.

1. Extend security-test-client in a dedicated isolated Docker test project. Targets must come from that project's allowlist; do not attack host services or external infrastructure.
2. Test altered facts, contract substitution, unsigned scope fields, wrong device/window identities, count inconsistencies, invalid signatures, replay across epochs/restarts, duplicate parts, reordered valid parts, same-scope signed forks and oversized/deep inputs.
3. Test loss of raw messages, evidence-only loss, whole-window blackout, one missing device, missing metrics, late capsules, clock jumps, startup with no data and crash during each meaningful ledger/outbox/receiver transaction.
4. Flood routine LOW traffic and then critical events. Measure both critical latency and evidence service, bounded queues/spools/assemblies, compaction behavior and CPU/memory. Include the critical-only flood where finite-capacity limits must be visible.
5. Test no receiver-feedback dependency using data-flow tests and observed cross-boundary traffic. Verify actual network memberships and Fog-to-Edge application failures. Keep host-administrator and UDP bidirectionality limits explicit.
6. Run exhaustive small-trace tests: enumerate observations, predicates and manageable receive/drop/reorder patterns; compare each TRUE/FALSE decision with the independent original-ingress oracle. Run larger seeded property tests without claiming exhaustive proof of all executions.
7. Treat UNKNOWN as a separate outcome. Removing supporting evidence may make a answer UNKNOWN, but cannot make a wrong definite answer. Valid redundant facts may preserve a definite answer.
8. Demonstrate the trust boundary: a trusted signer fabricating a internally consistent hidden-input summary is outside cryptographic detection. Record that limitation rather than expecting a signature check to detect it. Likewise, loss before gateway admission is not guaranteed detectable.
9. Export scenario, expected/actual outcome, scoped detected status, timestamps, latency, queue/resource data and reason as JSON/CSV. Store packet evidence where available. Use bounded runs with cleanup only for this test deployment.
10. Fix actual failures in the affected implementation and rerun the relevant checks.

Acceptance: all required local scenarios have recorded results, no wrong definite result occurs in tested in-scope traces, and undetectable/out-of-scope cases are explicitly distinguished from successfully detected attacks.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N9.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

## N10: Reproducible Baselines and Ablations

Individual file: [10-reproducible-evaluation.md](10-reproducible-evaluation.md).

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N10: REPRODUCIBLE BASELINES AND ABLATIONS

Prerequisite: N9 has no unresolved in-scope correctness failures.

Goal: determine objectively whether the coupled mechanism earns its evidence cost.

1. Add coverage workloads/runners/analysis alongside existing experiments. Reuse source fingerprinting, seed manifests, no-overwrite outputs and confidence-interval conventions. Keep simulation results distinct from actual Docker/UDP measurements.
2. Compare unfiltered FIFO with gap-aware monitoring; current adaptive/legacy analytics; signed heartbeat plus sequence-gap monitoring; simple signed predicate summaries with fixed admission; full RCCD; and an always-UNKNOWN control. Do not weaken the heartbeat/simple-summary baselines.
3. Ablate semantic preservation, advance evidence reservation, service reservation, evidence repeats and durable recovery separately. Any intentionally unsafe logic variant is restricted to the test harness.
4. Give each configuration paired original-ingress traces, contract/device sets, offered loads, capacity schedules, deadlines and forward fault seeds. Enforce the same total byte budget including evidence, heartbeat, signatures, framing and repeats. Record divergences rather than silently treating unequal buffers or admission policies as equivalent.
5. Cover light/moderate/near-capacity/overload/burst/critical-storm traffic; independent loss, burst loss, evidence-only loss, reorder/delay and a local capacity step. Start with a manageable declared matrix and bounded run durations. At least five paired trials per reported configuration; ten when practical.
6. Measure correct definite decisions/all rule-window opportunities by deadline, false FALSE, false TRUE, UNKNOWN rate/duration, decisions per KiB, incident recall, latency quantiles, raw-detail availability, payload/evidence/repeat/wire bytes, queues, drops, CPU/memory and storage. Unknown is neither false nor a successful detection. Define zero denominators and missing samples.
7. Use an independent full accepted-ingress oracle. Report upstream generation loss separately, outside that oracle scope. Include fault schedules and original traces so all verdicts can be recomputed.
8. Report mean, median, sample SD, sample counts and paired-difference 95% confidence intervals using a justified method. Do not use packets from one run as independent repeated trials or combine incompatible workloads.
9. Produce regenerable matplotlib PNG/PDF figures and raw CSV for decision yield versus budget, UNKNOWN versus loss, false definite decisions, evidence overhead, critical latency under congestion and reservation/recovery ablations.
10. Generate an objective experiment_summary.md and data dictionary. If ordinary summaries match or beat RCCD, disclose that. Measured zero errors is not proof of patentability or universal correctness.

Acceptance: raw artifacts reproduce the published tables/figures; strongest baselines and cost are visible; the conclusion follows the measurements, including negative results.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N10.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

## N11: Local Demo and Invention Disclosure

Individual file: [11-local-demo-and-disclosure.md](11-local-demo-and-disclosure.md).

```text
Work in C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode.
Read applicable AGENTS.md and docs/novelty-roadmap/README.md, design.md and prior-art.md before editing. Implement only this phase. Inspect current files and earlier phase reports; preserve existing user changes, credentials, signing keys, database volumes and baseline deployments. Use only local Python/Docker services. Do not create AWS/cloud resources or a Fog-to-Edge control path. Extend existing patterns and keep dependencies small. Describe the candidate as proposed research, not established novelty or patentability.

PHASE N11: LOCAL DEMO AND INVENTION DISCLOSURE

Prerequisite: N10 contains reproducible measurements and explicitly stated limits.

Goal: package the functioning local research project and a defensible technical disclosure.

1. Build one deterministic local demo using the existing five devices and Docker services: normal telemetry reduction; a real registered predicate match; a cross-device incident; missing raw traffic with sufficient capsule facts; evidence-only loss producing UNKNOWN; capsule tampering; and restart/recovery. Show the exact received scope and evidence for each outcome.
2. Provide idempotent Windows PowerShell setup/start/status/demo/stop/restart scripts. Resolve Docker through scripts/docker_support.py or an equivalent current helper. Use the actual project directory and isolated software-data-diode-coverage project. Preserve .env, main signing keys, main database volumes and baseline deployments.
3. Validate fresh research-state initialization and subsequent restart, non-root writable-volume permissions, migrations, health semantics, loopback host ports and dashboard accessibility. Use automatic subnet selection. Do not use down -v as a routine stop or delete other deployments to fix startup.
4. Add a faculty-oriented explanation of the problem, the coupled reduction/reservation mechanism, the precise scope, experiment methods, observed tradeoffs and software-isolation limits. Link every claimed technical effect to implementation and measured evidence.
5. Create an invention disclosure draft, labeled NOT FILED and NOVELTY UNESTABLISHED. Describe the problem, proposed technical method, state machines, actual implementation, figures, test results, alternative embodiments and closest prior art. Do not draft sweeping claims to all software diodes, authenticated summaries or UNKNOWN monitoring.
6. Add a claims-to-evidence matrix distinguishing established building blocks, proposed coupling, implemented behavior, measured results and legal issues requiring professional assessment. Explain obvious-combination risk, jurisdiction-dependent software eligibility and patentability versus freedom to operate.
7. Record actual human engineering contributions for faculty review; do not invent inventorship, filing dates, patent numbers or attorney approval.
8. Update README/project docs only after the implementation exists. Preserve historical phases and results as reproducible baselines. Document safe rollback to existing HTTP mode.
9. Rerun required local configuration, targeted regression, security, migration/restart and demonstration checks. Provide exact commands, local URLs and outstanding limitations. Do not publish code, submit a paper, file a patent or deploy externally as part of this phase.

Acceptance: another person can start and restart the local demo, reproduce its evidence and understand the narrow candidate without being told that novelty, physical one-way enforcement or legal eligibility has been established.

Run the relevant checks, fix failures attributable to this phase, and save docs/novelty-roadmap/reports/N11.md with changed files, exact verification commands/results, limits and next-phase prerequisites. Report unavailable Docker or other required checks honestly. Finish this phase without starting the next one.
```

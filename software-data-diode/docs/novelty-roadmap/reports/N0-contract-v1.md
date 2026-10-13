# N0 contract freeze: RCCD v1

Status: specification frozen on 2026-10-13. Identifier: N0-contract-v1.
This document defines future implementation requirements. It implements no evaluator, runtime model or configuration flag.

## Authority and change control

N1-N11 must follow these decisions. This document resolves ambiguity in roadmap-1. Changing predicate meaning, scope, timing, numeric interpretation or population requires an explicit versioned specification change, new contract hashes and new comparison traces. Changes cannot silently reinterpret stored capsules.

## Observation boundary

The population is the original normalized telemetry accepted by the trusted Edge Gateway before its reduction policy, for the declared device and ingress window.

Acceptance in the future mode means the admission transaction commits observation identity, membership, facts and relevant obligation state. Requests refused before that point are not accepted observations. Generated samples, upstream drops, uninstrumented events and untrusted sensor truth remain outside the completeness claim.

Observation identity is (ledger_epoch, device_id, ingress_sequence). Sequence numbers are per device within the durable ledger epoch. Ordinary restarts retain the epoch and counters. Outgoing UUIDs and outgoing transport sequences remain separate identifiers.

An accepted observation with an unexpected telemetry type or an unavailable required metric is unresolved for that condition, not silently removed from its population.

## Time and window identity

- Fixed width: 10 seconds; nonoverlapping tumbling windows.
- Membership: trusted gateway ledger-admission UTC, never signing time, Fog receive time or device source time.
- Precision: integer UTC microseconds.
- Alignment: Unix epoch. window_index = floor(ingress_utc_microseconds / 10000000).
- Interval: [window_index * 10 seconds, (window_index + 1) * 10 seconds). An observation exactly at the upper boundary belongs to the next window.
- Stable identity: (ledger_epoch, device_id, window_index, contract_hash).
- Ingress assignment and closure are serialized with admission. A closed membership set is immutable.
- Monotonic elapsed time drives scheduling and detects time-continuity problems. It does not silently redefine UTC membership.
- Clock discontinuity, uncertain recovery or premature closure produces signed limitations. No synthetic historical healthy/empty windows may be generated to cover downtime.
- Source timestamps are signed provenance only. Three conditions in one window are not proof of simultaneous physical events.

N1 must supply an injected clock interface and deterministic boundary tests. N2 must prove that crash recovery does not reopen a sealed identity with a different population.

## Registered contract

Resolve and validate a contract before using it. Its semantic content includes:

- contract/protocol version, observation boundary and numeric model;
- named device registry with expected telemetry types and metric units/paths;
- atomic predicate identifiers, inequality operators, thresholds and count K where relevant;
- rule expression identifiers and AND/OR structure;
- window width, alignment, boundary convention and time basis;
- minimum observation requirements and evidence/structure limits;
- policy-relevant lifecycle and validity settings.

The normalized validated semantic document, including resolved defaults, is serialized deterministically and SHA-256 hashed. Hash the complete validated document, rather than a selectively chosen list of fields. Keys, types and arrays that have semantic order must be handled consistently. Reject duplicate JSON keys, unknown semantic fields, duplicate identifiers and nonfinite values.

N1 defines the concrete schema and golden bytes for this frozen interpretation. Do not manually invent a claimed live contract digest during N0.

Provision the same contract locally on both sides through read-only files. Fog does not send rule subscriptions or configuration changes to Edge. A change takes effect at a new window boundary and has a different hash. New Fog-only predicates cannot claim facts about previously withheld values.

## Numeric and metric interpretation

Use finite IEEE-754 binary64 values in the Python v1 prototype, with the same numeric interpretation declared in each contract. Compare parsed values and thresholds directly with the selected inequality. Do not add implicit rounding, tolerance or quantization.

Reject nonnumeric/boolean condition values and nonfinite thresholds. If a required accepted measurement cannot be interpreted under the contract, classify it unresolved. Counts and K are integers; K and minimum_samples must be positive.

Use explicit metric paths. Examples: cpu_usage, temperature, measurements.packets_per_second, measurements.failed_logins and measurements.vibration_mm_s. Do not flatten arbitrary measurements over root fields.

The existing engine gives root CPU/temperature fields precedence while the existing Fog extractor lets measurements override those names. RCCD must not inherit this ambiguity. N1 must test explicit paths and threshold-adjacent binary64 values. Exactness means exact for the accepted normalized binary64 observations, not exact decimal or physical-world truth.

## Predicate language

Atomic operators:

1. EXISTS(device, metric_path, inequality, threshold).
2. COUNT_GE(device, metric_path, inequality, threshold, K).

Inequalities: >, >=, <, <=. Composite rules are bounded AND/OR expression trees of registered atomic conditions in the same window.

No arbitrary code, equality, NOT, nested time windows, joins over arbitrary device sets, ordered-event rules, continuous duration, rate derivatives, moving-average or z-score guarantees are supported in v1. Existing descriptive analytics remain available as legacy analytics.

minimum_samples defaults to 1 per atomic condition's declared device population. An empty window/heartbeat cannot justify a negative result.

## Facts and possible answers

For a closed condition scope with N accepted observations:

- m = matching observations;
- n = nonmatching observations;
- u = unresolved observations;
- N = m + n + u;
- matching count lower bound L = m;
- matching count upper bound U = m + u.

A full accepted trace with unresolved measurements is itself partially informative. Its oracle therefore has the same three possible truth values, but computes them independently from original observations.

EXISTS is COUNT_GE with K=1.

- TRUE when authenticated known matching evidence establishes L >= K.
- FALSE when a closed admissible scope meets its minimum observation requirement and its supported upper bound U < K.
- UNKNOWN otherwise.

A valid positive witness may establish TRUE before closure because additional observations cannot remove the witness. Absence of a witness is not a negative proof. Pending windows, absent capsules and missing transport parts have no finite negative bound merely because nothing arrived.

Raw witness identities must bind ingress scope through signed fields. A source timestamp or post-policy UUID alone is insufficient. Deduplicate by original observation identity, and do not add raw witness counts to capsule counts when they cover the same observations.

Capsule count contradictions, impossible ranges or signed facts inconsistent with known original witnesses are verification/conflict findings. Authenticated but contradictory same-scope artifacts invalidate their trust premise; reassess the affected scope visibly.

## Composition and health

Use strong Kleene logic: FALSE AND anything is FALSE; TRUE OR anything is TRUE; TRUE AND UNKNOWN and FALSE OR UNKNOWN are UNKNOWN.

A negative AND-rule can be established by one complete negative condition even if another condition is unknown. Record that minimal supporting basis and show missing-device coverage separately. Rule FALSE is never a global healthy/safe verdict.

Artifact verification, rule truth, device health, continuity and alert severity are independent fields. A valid signature does not turn an unknown predicate into FALSE or prove physical truth.

## Assurance and evidence obligations

Online RCC facts have AUTHENTICATED_SUMMARY assurance under the trusted-gateway assumption. A commitment is not an independent proof of withheld input values. Offline recomputation requires the actual disclosed input scope and is a distinct assurance result.

Update original facts before reduction and reserve bounded storage/forward evidence costs before irreversibly reducing routine data. Atomically account for admission, obligation and disposition changes. Publish no successful durability or semantic-preservation claim when the corresponding transaction did not commit.

Raw selection, semantic representation, local send attempt and confirmed Fog receipt are different events. Retried/repeated capsules reuse identical signed bytes. Local overflow can destroy raw detail while a previously maintained exact condition fact still represents it.

Evidence frame limits, repetitions, closure frequency, service share and link capacity must be declared and validated together. 1,200 bytes is the planned maximum signed UDP datagram payload. The initial 10% evidence share is an experimental setting, not a proved delivery guarantee.

## Independent raw-trace oracle definition

N1 will implement this oracle; N0 defines it only.

Input: the resolved contract, immutable original accepted observations with ingress identities/times, and explicit closure/time-limit information.

For each device/window/condition:

1. Enumerate original accepted observations directly from the retained input trace.
2. Resolve the declared metric path and classify the original value independently with explicit inequality branches.
3. Count matching, nonmatching and unresolved records without reading policy decisions, transformed payloads, capsules or receiver results.
4. Derive the three-valued result using the closed-scope/observation rules above.
5. Combine atomic results with an independently written truth table.

The oracle may use validated contract data and canonical trace parsing. It must not call the production capsule evaluator, InformationEngine, reduction policy or their accumulator methods.

Exhaustively test small complete traces against straightforward Boolean predicates; separately test unresolved traces and partial receiver evidence. A definite Fog answer must equal the full-trace oracle answer for the same scope. If the oracle is UNKNOWN, an unsupported definite Fog answer is a failure.

The input corpus remains available to the experiment harness, not to the deployed Fog verifier. Deadline results count all registered rule-window opportunities, including unknown and empty scopes, so abstention cannot inflate accuracy.

## Seed demonstration rules

These settings are synthetic and are chosen from actual generator metric paths.

| Rule | Conditions in the same ingress window |
|---|---|
| environmental-threshold | EXISTS edge-device-01.temperature >= 38 |
| resource-threshold | EXISTS edge-device-02.cpu_usage >= 90 |
| network-threshold | EXISTS edge-device-03.measurements.packets_per_second >= 8000 |
| security-threshold | EXISTS edge-device-04.measurements.failed_logins >= 5 |
| industrial-threshold | EXISTS edge-device-05.measurements.vibration_mm_s >= 8 |
| incident-correlation | resource-threshold AND network-threshold AND security-threshold |
| process-correlation | environmental-threshold AND industrial-threshold |
| repeated-security-observations | COUNT_GE of security-threshold's inequality with K=2 |

The last rule counts telemetry observations meeting failed_logins >= 5; it does not sum actual login attempts. CPU 90 aligns this seed example with the existing synthetic correlation threshold. All these rules are proposed contracts, not currently active RCCD rules.

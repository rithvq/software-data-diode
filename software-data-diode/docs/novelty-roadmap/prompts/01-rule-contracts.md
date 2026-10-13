# N1: Rule Contracts and Exact Semantics

Copy the entire prompt below into the coding agent. Complete earlier phases first.

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

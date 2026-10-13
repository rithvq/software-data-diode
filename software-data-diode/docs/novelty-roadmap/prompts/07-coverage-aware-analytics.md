# N7: Coverage-Aware Rules and Alerts

Copy the entire prompt below into the coding agent. Complete earlier phases first.

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

# N4: Coupled Reduction and Evidence Admission

Copy the entire prompt below into the coding agent. Complete earlier phases first.

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

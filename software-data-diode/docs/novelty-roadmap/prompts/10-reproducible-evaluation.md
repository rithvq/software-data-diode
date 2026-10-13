# N10: Reproducible Baselines and Ablations

Copy the entire prompt below into the coding agent. Complete earlier phases first.

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

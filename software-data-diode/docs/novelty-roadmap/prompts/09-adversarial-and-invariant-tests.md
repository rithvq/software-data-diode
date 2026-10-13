# N9: Security and Scoped Correctness Validation

Copy the entire prompt below into the coding agent. Complete earlier phases first.

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

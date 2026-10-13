# N0: Baseline and Specification Freeze

Copy the entire prompt below into the coding agent. Complete earlier phases first.

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

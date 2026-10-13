# N8: Evidence Coverage Dashboard

Copy the entire prompt below into the coding agent. Complete earlier phases first.

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

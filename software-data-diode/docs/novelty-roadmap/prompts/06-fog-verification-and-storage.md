# N6: Fog Verification and Persistence

Copy the entire prompt below into the coding agent. Complete earlier phases first.

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

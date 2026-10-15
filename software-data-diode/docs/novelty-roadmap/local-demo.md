# N11 Local Research Demo

Proposed research only. NOT FILED; NOVELTY UNESTABLISHED. Read the
[faculty explanation](faculty-explanation.md), [technical disclosure](invention-disclosure.md)
and [N10 negative findings](reports/N10.md) before presenting it.

## Safety and Prerequisites

Use Windows PowerShell, Docker Desktop's Linux engine and the existing Python
3.11+ `.venv`. No AWS, external targets, new infrastructure services or publishing.
The wrappers resolve the project from their own location, not your current folder.
They use `scripts/docker_support.py` for per-user/system Docker installations.
Open Docker Desktop and wait for its engine before running the commands.

For a genuinely new checkout only, create `.venv` and install the existing pinned
development requirements. Do not replace an existing environment, `.env` or keys:

```powershell
Set-Location -LiteralPath 'C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode'
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -c constraints.txt -r requirements-dev.txt
```

All N11 credentials are separate: a new DB password under ignored `.local/n11/`,
a private key in an Edge-only named volume, a public trust profile in a read-only
shared volume, private ledger/device/replay volumes and service-specific audit
volumes. Do not publish `.local/` or dump resolved Compose configuration into reports.
Existing main keys, `.env`, PostgreSQL and historical results are not inputs to setup.

**Older research deployment:** scripts refuse to adopt existing containers without
the N11 ownership label. They do not automatically stop, upgrade, rotate or delete
them. On this machine `software-data-diode-coverage` already existed before N11.
Use the explicit validation namespace below to keep it intact. Do not remove that
older deployment to make these commands succeed.

## Fresh Default Project

On a machine where the exact research project name is unused:

```powershell
Set-Location -LiteralPath 'C:\Users\Rithvik Kumar\Desktop\fogedge\software-data-diode'
.\scripts\coverage-setup.ps1
.\scripts\coverage-start.ps1 -Build
.\scripts\coverage-status.ps1
.\scripts\coverage-demo.ps1
```

Default project: `software-data-diode-coverage`. Dashboard:
http://127.0.0.1:38501. Choose **Evidence Coverage**. Setup allocates non-overlapping
local subnets after inspecting Docker IPAM and host routes, including a Fog-only
host bridge. Only the dashboard is published, on IPv4 loopback. The gateway,
database and UDP ports are not published.

`-Build` builds local service images using the existing Dockerfiles. It may need
the pinned base images/packages if not cached. No source/config update should be
applied to a running ledger without reviewing its immutable configuration binding.
Repeated start uses `--no-recreate`; it is not an implicit hot image upgrade.

## Preserving This Machine's Existing Research Deployment

N11 was verified in this explicitly isolated project, with separate state:

```powershell
$Project = 'software-data-diode-coverage-n11-1a11c0de0004'
.\scripts\coverage-setup.ps1 -Project $Project -DashboardPort 39501 -CachedImagesFrom 'software-data-diode-n9-d96e30503021'
.\scripts\coverage-start.ps1 -Project $Project
.\scripts\coverage-status.ps1 -Project $Project
.\scripts\coverage-demo.ps1 -Project $Project
```

Optional deployment verification (project-scoped PostgreSQL transactions,
memberships/reverse failures, non-root writes and loopback health):

```powershell
.\.venv\Scripts\python.exe scripts/coverage_local.py verify --project $Project
```

Dashboard: http://127.0.0.1:39501. The explicit cached-image option pins immutable
local image IDs, mounts current application/shared source read-only, and uses the
existing coverage dashboard/monitoring image dependencies. It is an offline local
reproduction option, not a newly built release-image attestation. On another
machine omit this option and use `-Build`. Choose a new twelve-hex validation suffix
and an unused loopback port for a **fresh** initialization check; ordinary restart
must reuse its existing name/state, not create a new epoch.

## What the Demo Does

The five real device containers are idle between runs. The host starts five bounded
device-local tasks concurrently; these post through ordinary gateway admission.
They do not send precomputed capsules. The native SQLite ledger, InformationEngine,
reservation/outbox service, UDP diode, Fog verifier, PostgreSQL and rule monitor run.

Each stage submits five original observations per device in one aligned ten-second
window, safely away from its boundaries. Time/UUID/key identities vary by run;
input values, stage sequence, registered contracts and expected outcomes do not.

| Stage | Expected evidence/outcome |
|---|---|
| Normal routine data | Below-threshold FALSE in accepted scope; raw reduction recorded |
| Registered match | Environmental EXISTS temperature >= 38 becomes TRUE |
| Cross-device incident | CPU >= 90, packets/s >= 8000 and failed logins >= 5 each match in the same ingress window |
| Raw loss | Forwarder drops raw frames; five independently received capsules still support TRUE |
| Evidence-only loss | Negative raw passes, capsules are dropped; no complete negative proof, so UNKNOWN |
| Tampering | Signed evidence parts are altered, rejected; after Fog grace the scoped decision is UNKNOWN |
| Recovery | Same gateway epoch/counters survive restart; a new admitted match again becomes TRUE |

Thresholds are synthetic, not physical safety limits. The incident does not assert
simultaneous physical events. Normal routine reduction requires local pressure:
the derived **demo-only** policy sets the engine's message-capacity estimator to
1 message/s and queue bound 64; physical modeled link stays 131,072 bytes/s with
10% evidence, 45% protected and 45% routine shares. This is an illustrative local
estimator setting, not a performance measurement or the baseline configuration.

Fixed forward-link faults are installed locally before admission. They never
consume Fog readiness/metrics or feed policy decisions. All scheduled bytes remain
charged even when a test fault discards them. No receiver reply is requested.
Fault injection requires both the N11 flag and allowlisted project name.

Results go to a fresh `docs/novelty-roadmap/evidence/N11/<UTC>-<suffix>/` directory:
five native receipt/original trace files, exact capsule bodies/verification records,
rule revisions/reasons/artifact references, raw receipts, rejection outcomes,
fault-frame hashes, restart identities, independent oracle comparisons and
JSON/CSV scenario results. UNKNOWN is not counted as a detected attack or false answer.

Select the recorded window/rule in Streamlit; inspect scope, contract hash,
AUTHENTICATED_SUMMARY assurance, continuity and support. A missing predecessor is
not automatic invalidation of an independently verified later capsule. The UI
does not read the Edge ledger. Host-side audit/oracle reads are offline test checks,
not a Fog-to-Edge control channel.

## Safe Stop, Restart and Rollback

```powershell
.\scripts\coverage-stop.ps1 -Project $Project
.\scripts\coverage-restart.ps1 -Project $Project
.\scripts\coverage-status.ps1 -Project $Project
```

For the default name omit `-Project`. Stop uses only `compose stop --timeout 30`;
restart stops/starts the same project. It never uses `down -v`, prunes Docker,
replaces keys or resets epochs. Quit Docker Desktop after stopping the project.
Reopen Desktop, then start the same project. Migrator/init reruns are idempotent
and fail visibly on identity/configuration mismatch rather than replacing state.

**Finite-session limit:** N4 currently retains at most 256 immutable signing records;
empty closures also consume history. This is not an indefinitely running appliance.
Stop after the demonstration. Before admission the demo requires conservative
remaining signing-history headroom; it refuses if more than 136 capsules are
already retained. This is not a guarantee against a prolonged timeout consuming
additional state. Inspect failures rather than deleting volumes to bypass them.
Long-run retirement/compaction and the missing historical N4 report
remain unresolved. A few repeat demos/restarts fit; unlimited repetition does not.

For HTTP rollback, stop **only** N11. Use the unchanged baseline project with its
original Compose files, `.env`, volumes and keys (do not merge coverage overrides):

```powershell
docker compose -p software-data-diode --profile full start
docker compose -p software-data-diode --profile full ps
```

This resumes already created baseline containers. If baseline containers were
never created, follow the existing README's setup procedure; do not reuse N11 state.
HTTP is the named rollback baseline, not an ACK-free research transport. Its
dashboard is normally http://127.0.0.1:8501 with the baseline's existing port setting.

## Troubleshooting

- Docker pipe/daemon error: start Docker Desktop; do not regenerate credentials.
- Older deployment ownership refusal: use a new allowed validation namespace.
- Port occupied: choose a new project's `-DashboardPort`; no global stop commands.
- Budget/configuration mismatch or signing capacity: retain state; review the
  error. Do not reset the ledger or switch policy on an existing bound epoch.
- Nonzero demo: retained evidence is a failed run, not a success. Do not overwrite it.
- Blank/dim page: check status/health and the existing N8 pause/refresh controls;
  N11 adds no full-page refresh loop.

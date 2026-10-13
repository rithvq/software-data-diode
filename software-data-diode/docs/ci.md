# Continuous integration

The workflow is `.github/workflows/ci.yml` at the **Git repository root**.
It runs on every push, pull request, merge-queue test commit and manual dispatch.
There are no branch/path filters or manual phase-number updates.

## What runs

| Check | Work |
|---|---|
| Python 3.11 / Ubuntu 24.04 | All discovered pytest cases, critical Ruff checks, compilation, configuration and dependency consistency |
| Python 3.12 / Ubuntu 24.04 | The same regression suite on a second supported version |
| Python 3.12 / Windows 2022 | Windows regression checks, including SQLite admission/recovery and signed capsules |
| Workflow syntax | Checksum-verified actionlint 1.7.12 on the Linux 3.11 runner |
| Docker Phase 1 | Build the one-device baseline; verify forward delivery, instrumentation and blocked reverse access |
| Docker Phase 2 | Initialize fresh volume-local keys; verify signed delivery, attacks, audits and network/key isolation |
| Full Stack and Recovery | Build all five devices, PostgreSQL, analytics, dashboard, Prometheus and Grafana; rerun migrations; audit isolation, persistence and deliberate Fog/PostgreSQL outage recovery |
| Isolated Adversarial Tests | Run the existing local-only simulator against its dedicated Compose profile; require a successful simulator exit |
| CI Passed | Fail unless every preceding suite succeeded; failed, cancelled and skipped suites do not pass |

Pytest discovery automatically includes later phase tests. Existing N0-N3 contracts,
ledger, oracle and capsule tests are part of the full suite. The experimental
runner/policy/chart helper tests also run. Full publication benchmark campaigns and
interactive browser visual testing are not run by this workflow.

New phases must add tests for their new behavior. Add/update explicit Docker checks
when a phase introduces a new deployment or protocol; automatic test discovery
cannot manufacture integration coverage. In particular, N3 has no live coverage
transport, so the normal Docker deployment remains unchanged and research mode
must not be enabled merely for CI.

## Safety and reproducibility

All Docker work runs on disposable **GitHub-hosted Linux runners**, never a
self-hosted runner or your Docker Desktop. No AWS resources or automatic deployment
are created. Deliberate outage tests and volume cleanup affect only those runner-local
projects: the standalone phase projects, `software-data-diode-audit` and
`software-data-diode-ci-security`.

`scripts/ci_runtime.py` refuses local/self-hosted use and existing `.env`/signing files.
It calls the existing setup script only on a clean hosted checkout, masks generated
passwords/tokens, and makes the ephemeral private key readable only by the
container UID 10001. The security report directory has the appropriate container
ownership. Your local credentials, keys, runtime state and volumes are not migrated
or reset.

The helper sends one synthetic CRITICAL message through an existing registered Edge
device and waits, with bounded retries, for five active devices, accepted data,
anomalies/alerts and healthy Prometheus targets. This avoids a fixed sleep or a
false failure caused by asynchronous startup.

Actions are pinned to verified official commit SHAs, checkout does not persist
credentials, and token permissions are `contents: read`. There is no
`pull_request_target` event or repository-secret dependency. Dependabot checks the
action pins monthly. Runtime dependencies retain the existing exact versions.
Security-test traffic remains inside the disposable Docker application networks.

JUnit, coverage XML/JSON/HTML, container status, bounded logs, runtime audit JSON and
security CSV/JSON evidence are retained for 14 days, including on failure.
The runtime auditor's new `--output` option writes `ci-results/runtime.json`;
its normal local output remains unchanged. Initial stack-lookup failures also write
a failure report, so CI does not mistake checked-in historical audit evidence for
the current run.
Only explicit report paths are uploaded, not `.env`, keys, database volumes,
complete container environment dumps or resolved Compose documents. Test credentials
are disposable; do not replace them with real secrets.

## Publish the workflow

This workspace's Git root is `C:\Users\Rithvik Kumar\Desktop\fogedge`, its current
branch is `master`, and no Git remote was configured when CI was added.
The workflow is therefore in `fogedge\.github`, not inside the application folder.
The workflow detects either application layout:

```text
Git root                         Git root
  .github/workflows/ci.yml          .github/workflows/ci.yml
  software-data-diode/              requirements-dev.txt
    requirements-dev.txt           shared/, tests/, scripts/, ...
    shared/, tests/, scripts/, ...
```

If publishing only the application's contents as a flat repository, include the
root `.github` directory too. Do not leave it one level below GitHub's repository root.

From the workspace Git root, inspect your state and connect the supplied repository
only if it is still missing:

```powershell
Set-Location "C:\Users\Rithvik Kumar\Desktop\fogedge"
git status --short
git remote -v
git remote add origin https://github.com/rithvq/software-data-diode.git
git fetch origin
git branch -a
```

Do not run `remote add` twice. If a remote already exists, check its URL first.
If the remote has divergent/unrelated history, reconcile that history before
publishing; do not force-push or reset your existing work.

Create a feature branch, stage the workflow and intended application phase changes,
and review the staged diff before committing:

```powershell
git switch -c ci/phase-verification
git add .github software-data-diode
git diff --cached --stat
git diff --cached
git commit -m "Add phase regression and Docker integration CI"
git push -u origin ci/phase-verification
```

Review everything staged: the current worktree contains earlier phase changes.
Do not include unrelated workspace AWS artifacts, credentials, signing keys,
database files or raw private observation archives. This setup does not commit,
push, rename branches or change your remote automatically.

Open the repository's **Actions** tab and the **CI** run. If Actions are disabled,
enable them in repository Settings > Actions. A manual dispatch becomes available
after the workflow exists on the default branch. A first-time fork contribution
may require a maintainer to approve its run.

## Require CI before merging

After the first CI run exposes the check:

1. Open repository Settings > Rules > Rulesets, or Settings > Branches.
2. Protect the actual default branch, whether `main` or `master`.
3. Require pull requests and the status check named **CI Passed**, with GitHub Actions as its source.
4. Require the branch to be up to date before merging, or use a merge queue.
5. Avoid bypassing the rule when a check fails.

Branch protection availability depends on repository visibility and your GitHub plan.
See [GitHub's required-status-check documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging).
For action pinning and restricted permissions, see
[GitHub's secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use).

Pushing a broken change does not automatically roll back software already deployed
on your computer. Prefer **phase branch -> CI -> reviewed merge -> local update**.
Required checks stop known failing changes from merging; they are not a promise of
100% coverage, bug freedom, physical one-way security or uninterrupted operation.

## Security CI source authorization fix

The 2026-10-13 hosted run passed the Python matrix, both Docker baselines and the
full-stack recovery job. The adversarial job instead reported `UNAUTHORIZED_SOURCE`
even for valid controls. Consequently `CI Passed` correctly failed; its gate must
not be bypassed.

Unlike the existing normal-service security launcher, CI uses a one-off
`docker compose run` container. That invocation needs `--use-aliases` so Docker DNS
registers `security-test-client` on the test networks. The diode and Fog authorize
the client's source IP against that service name. Without the alias, the tests
cannot reach signature, replay or flood validation.

The CI command now includes `run --build --use-aliases --rm security-test-client`.
See [Docker's Compose run options](https://docs.docker.com/reference/cli/docker/compose/run/).
No production/test allowlist, network membership, exposed port, cryptographic check
or final CI gate was weakened. A regression test binds this invocation to the
existing source allowlists.

A bounded local reproduction used the actual `shared.http.peer_allowed` function
in two temporary containers on private networks: the original invocation returned
HTTP 403; the alias-enabled invocation returned HTTP 200 for the same source IP.
Only public source was mounted read-only; no keys or host ports were used. Those
test containers/networks were removed, and other running projects were left alone.

Fix verification: the full isolated-state regression suite passed **485 tests**
in 18.43 seconds (one existing Starlette/httpx warning); critical Ruff checks,
actionlint workflow validation and `git diff --check` also passed. JUnit evidence is
generated locally at `ci-results/security-ci-fix-tests.xml` and is not committed.

Commit and push the fix to trigger a **new** CI run. Re-running an old failed job
still uses its old workflow revision. The complete hosted adversarial job must be
confirmed by that new run; the focused reproduction is not a claim that every
adversarial scenario has already been rerun.

## Python CI comparator fixture fix

The logs supplied on 2026-10-14 show the same failure on Linux Python 3.11/3.12
and Windows Python 3.12: `test_small_trace_comparator_has_matched_scope_config_and_actual_byte_budget`
asserted equal acceptance, but the coupled path accepted 6 messages and the
unreserved-summary path accepted 10. Each job otherwise passed 543 tests. The
Docker jobs succeeded; `CI Passed` correctly propagated the Python failures.

The comparison helper deliberately defaults to one cycle of outstanding evidence
debt. At a window boundary, the just-closed signed evidence has not yet been
serviced, while the next window requires advance reservations. A matched offered
trace and link capacity do not imply equal accepted populations with that tight
budget. Refusing unbudgeted input is expected behavior, not an admission bug.

`run_case` now accepts an explicit `AdmissionConfig` without changing its default
fixture or production settings. The equal-throughput regression supplies the same
two-cycle debt budget to both modes and verifies all 10 admissions, completed local
evidence attempts, exact scheduled-byte sums and per-cycle capacity limits. A
separate one-cycle regression preserves the 6 accepted / 4 refused result and
checks that no accepted coupled scope becomes unsupported. Neither test claims
confirmed Fog receipt or superiority of the coupled mode.

No workflow gate, security check, runtime reservation limit, credential or Docker
deployment was changed. Reproduce these focused checks with:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_coverage_admission.py -k comparator
```

Local verification used Windows `.venv` Python 3.12.6 with fresh temporary audit,
sequence, coverage, pytest-base and cache paths. The two focused comparator tests
passed. `python -m coverage run -m pytest -q` with those isolated paths passed
**545 tests in 62.83 seconds**, with one existing Starlette/httpx deprecation
warning. JUnit evidence is generated at `ci-results/python-ci-fix-tests.xml`
(ignored by Git). Repository-wide critical Ruff checks, focused full F checks,
example configuration validation, `pip check` and `git diff --check` passed.
Initial local sandbox/default temporary-directory permission errors were avoided
by using a fresh pytest base directory, without changing filesystem permissions.

Commit and push the fix to trigger a new workflow run. Re-running the old failed
revision will still run its incorrect fixture. Local Windows verification does not
replace confirmation of the Linux jobs in the new hosted run.

## Initial local verification of CI setup

Using the existing Windows `.venv` Python 3.12.6:

- `python -m pytest -q tests/test_ci.py --junitxml=ci-results/ci-tests.xml`: 26 passing focused cases.
- `python -m coverage run -m pytest -q --junitxml=ci-results/tests.xml`: 484 passed, one existing Starlette/httpx deprecation warning; 26.02 seconds.
- `python -m coverage xml -o ci-results/coverage.xml` and `python -m coverage json -o ci-results/coverage.json`: reports generated.
- Combined statement/branch coverage denominator: 71.5%. Coverage is reported, not hidden behind an arbitrary new threshold.
- `python scripts/validate_config.py --example`, `python -m pip check`, critical Ruff checks and source compilation: passed.
- Checksum-verified `actionlint 1.7.12 -shellcheck= -pyflakes= .github/workflows/ci.yml`: passed after moving runner-dependent runtime paths out of the unsupported job-env expression context.

The local test run used fresh temporary audit/sequence/coverage paths and no inherited
database URL. It did not overwrite historical phase reports or baseline coverage results.
New Docker CI jobs, fresh Linux dependency installations and actual GitHub workflow
execution have **not** been run yet. They are checked by the first pushed workflow;
local syntax/unit success is not a claim that the hosted integration jobs already passed.

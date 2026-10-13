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

## Local verification of this change

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

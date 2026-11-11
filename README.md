# Shared GitHub security workflow

## Prompt GitLab deploy override

`gitlab/prompt-gateway.yml` still includes the frozen Prompt delivery configuration
at `86e1cc1320389b5d0aa7ab92259daf87f2e15e61`. Its explicit `deploy` override replaces
the inherited image/before-script/script/rules, not the unused application-root
stub. Other jobs and scanner controller `55e51eba...` are unchanged.

The existing deploy job uses Python plus Git tooling, no application checkout,
services or producer artifacts. Only that job declares `VAULT_GITOPS_ID_TOKEN`
with audience `https://vault.downops.win/prompt-gitops`. The helper logs into
`auth/gitlab-ci` as `security-ci-prompt-deploy`, reads only
`downops/services/gitlab/gitops/instance-010`, and immediately revokes the short
Vault service token before Git work. The retained legacy `GITOPS_PUSH_TOKEN` is
explicitly removed and never a fallback. Git receives the Vault-fetched password
only through a child environment/ephemeral credential helper: no password URL,
argv value, credential file or stored helper result. Read errors preserve their
primary category if revocation also fails; standalone revocation failure blocks
deployment.
`vault_login_ok` means the returned lease passed the exact policy/type/TTL checks,
not merely that HTTP returned an auth object. Short, malformed or unsafe returned
client tokens are never used in further HTTP headers; only validated safe lease
strings are revoked, including safe leases whose authority is rejected.

Signed project/namespace/ref/push claims and the dedicated audience restrict the
reader. GitLab has no job-name or signed external-config-SHA bound claim here.
Deploy-only token declaration, immutable CI review and trusted Maintainers remain
part of the boundary, not cryptographic per-job isolation. MR/scanner/runtime
policies must not gain the GitOps record.

Git works with objects and a private index, not application scripts or checkout
filters/hooks. Exactly one regular canonical `k8s/app.yaml` image field must be
valid and become `registry.int.downops.win/downops/prompt-gateway:` followed by
`<stable-VERSION>-<8-character-source-SHA>`. Missing/legacy/malformed/duplicate
targets fail before idempotent success. Changed application source rejects stale
publication; a manifest-only descendant is accepted only if it already has this
source's desired tag. Pushes are normal fast-forward operations with at most
three fresh-guarded attempts, never force pushes.
Only after verified writeback/already-desired state, the helper notifies the
existing private Argo refresh-only hook with the actual SSH repository/main ref.
It never syncs or patches a workload. A failed refresh fails the job while keeping
the successful writeback revision in safe metadata; webhook200 alone is not Ready.

An unresolved `REVIEWED_C2_SHA_REQUIRED` sentinel must block activation. Parent first
reviews/publishes helper commit C2, then replaces the sentinel with that exact
40-character commit and publishes wrapper W2. Only project10's external CI pin
then moves to W2 under approval; existing GitHub callers and scanner CODE55 stay
unchanged. VaultOps STAGED metadata is not actual OIDC/delivery proof. Keep the
old CI variable until real injection and exact GitOps/Ready rollout are verified.
Publication alone does not activate the flow: project10 must select the reviewed
W2 pin and actual authenticated injection/writeback/delivery must be proved.
The C2 review includes the inactive prepared wrapper and its contract tests;
do not activate that sentinel-bearing wrapper. W2 is the subsequent resolved-pin
revision, avoiding a self-referencing helper commit hash.
Next use a meaningful Prompt documentation repair MR, full current-head gates,
and a normal MAIN merge/push. No manual deployment-only pipeline or forged source.

Offline tests cover synthetic Vault failures, no legacy fallback, primary-error
preservation, manifest guards, stale/racing pushes and the actual wrapper override.
No live JWT, GitLab push, tooling-image qualification or rollout is claimed by them.

`.github/workflows/dependency-track-scan.yml` is the single reusable security
entrypoint. It builds the exact PR merge candidate without credentials, generates
a runtime-image CycloneDX SBOM, waits for Dependency-Track, and evaluates the
assigned SonarQube quality gate using the Dependency-Track plugin metrics.

The separate `test-security-control.yml` runs controller unit tests; it is not a
second product security implementation.

## Consumer configuration

Use a reviewed, immutable **40-character commit SHA**, never a moving `main` tag:

```yaml
name: Security
on:
  pull_request:
    branches: [dev, main] # Use the repository's actual targets.
permissions:
  contents: read
jobs:
  security:
    name: Security
    permissions:
      contents: read
      pull-requests: read
      actions: read
      statuses: write # Trusted context/final jobs only; build remains contents-read.
      id-token: write
    uses: noelnovo/.github/.github/workflows/dependency-track-scan.yml@<reviewed-40-character-commit>
```

Do not pass `secrets: inherit`, scanner/API keys, a static Vault token, arbitrary
secret paths, or caller-selected control scripts. Signed caller repository ID and
the exact called-workflow path/SHA are bound in Vault. Unknown callers fail closed.

The final required check name stays:

- `Security / SonarQube + Dependency-Track (dev)`
- `Security / SonarQube + Dependency-Track (main)`

Require the appropriate final check and protect CI-control modifications. A job
name alone cannot prevent a contributor replacing caller CI with a forged check.
Branch enforcement is separately configured by the repository owner.

## Trust boundary and analysis order

1. A credential-free context job validates the PR head, current target and exact
   merge-commit parents through GitHub.
2. A fresh hosted build runner executes the candidate Dockerfile with contents-read
   permission only: no Vault, OIDC, registry login or scanner keys. Pinned Syft
   generates the resolved runtime-image SBOM.
3. A different fresh runner executes literal pinned controller code. It fetches
   candidate source as data and accepts only the digest/size/path-verified,
   same-run SBOM artifact. PR scripts, hooks and scanner settings do not execute.
4. Job-time OIDC obtains four project-scoped Vault records: uploader, analysis
   token, read-only plugin key, project-settings token. Recovery passwords and
   unrelated projects are denied; no secret is a workflow output.
5. DT processing finishes, plugin settings reconcile from Vault, Sonar analyzes,
   and every configured DT condition must be present in that exact analysis.
   Sonar's configured gate—not a hard-coded severity threshold—decides success.
6. Head/base/candidate are rechecked before success. Missing, stale, failed,
   cancelled or skipped producer evidence fails the always-evaluated final job.

Shared workflow and per-project analysis queues use `queue: max`; their group
names are stable across old/new pins so migrations cannot race shared DT state.

Image profiles can declare reviewed `coverage_sources`, optional `python_sources`
and trusted Sonar report settings. The credential-free image build runs real tests
and exports `coverage/lcov.info` and, when selected, `coverage/python.xml` through
the Dockerfile's `security-coverage` stage (`/lcov.info` and `/python.xml`). SBOM
and coverage travel in the SAME immutable candidate/run/attempt/digest-verified
artifact. Private analysis accepts only the expected BOM/report files, bounded
regular inputs, exact reviewed source paths present in the fetched candidate,
valid line/count data and all required source records. LCOV permits fixed `/app/`
path mapping. Python XML also permits `/srv/` and uniquely allowlisted basenames;
its normalized filenames still refer only to actual reviewed candidate files.
Declarations/entities, traversal, duplicates and oversized reports are rejected;
line/hit/branch data are never invented. Missing/invalid coverage fails
closed before scanning. No test/build command executes with scanner secrets,
no fabricated report or production-code coverage exclusion is added. Test-only
files are explicitly classified as tests in the reviewed profile.
Genuine declaration-only `.d.ts` LCOV records retain their zero line/function/
branch totals; ordinary executable sources still require actual line data.

The GitLab adapter uses these same validators. Its existing same-pipeline receipt
adds an opt-in coverage path/size/digest map, checked with project, pipeline,
head/base/target and full BOM digest before credentials are read. Profiles without
coverage retain their original receipt and artifact behavior. Tests remain in the
existing credential-free producer; the credentialed job only consumes report data.
This is not new isolation for the accepted privileged/shared GitLab executor.

Gate evidence must include every assigned `new_dependencytrack_*` **and**
`dependencytrack_*` condition for the exact completed project analysis. Missing,
non-numeric, stale or ERROR evidence cannot produce success. Thresholds come from
the assigned Sonar gate, never an independent hardcoded severity policy. A metric's
`new_` name does not prove SCM-delta semantics; this controller does not compute
such a delta or change the plugin's fixability heuristic.

## Register another product

Review a profile in `security/profiles.json`: immutable repository ID/name,
targets, service-instance mapping, role name, source directories and fixed build
arguments. Provision separate project-scoped uploader/analysis/plugin/settings
identities in Vault. Bind OIDC to the exact new called-workflow path and commit;
keep recovery credentials outside the CI policy.

Profiles are part of the pinned controller, not live mutable configuration.
Release an onboarding change in this order: commit/review/test the profile and
controller; update both literal controller checkout/verification pins and the
contract-test pin to that reviewed code commit; publish/test the workflow commit;
bind Vault to that exact workflow commit; then update the application's caller.
A profile edit on `main` alone does not affect a previously pinned consumer.

Build adapters support runtime OCI images (Dockerfile + Syft) and Android
(Temurin21, Android36, Gradle unit tests + resolved CycloneDX/compiled bytecode).
Android protected push callers can reuse the same-run validation SBOM/classes
instead of rebuilding. All build/artifact handling happens on the credential-free
VM. The scanner VM accepts only bounded approved bytecode/BOM paths as data,
ignores source build outputs/settings and never executes Gradle or artifacts.

Android's profile preserves required commit statuses
`security/sonarqube-dtrack-dev` and `security/sonarqube-dtrack-main` from trusted
context/final jobs, with `wallettracker-security-analysis` serialization shared
with the old producer during migration. The build job has no status-write or
OIDC permission. Post-merge validation retains its plain `security` aggregate
job so existing release-evidence checks still require successful security before
signing; it does not change signing/publication permissions or approvals.

This workflow version requires caller `statuses: write` for its trusted context
and final jobs. Existing Portfolio/Blog callers pinned to the earlier version
keep their existing permissions unchanged; upgrading a consumer requires review
of its workflow pin, Vault claim and permissions together. Other toolchains need
a reviewed credential-free adapter, never privileged caller commands. Registering
a profile does not itself add a caller or activate/change branch protection.

## Migration from the earlier generic uploader

The old artifact-only uploader accepted `sbom-artifact-name`, target URL/UUID,
static `DT_API_KEY` and optional `VAULT_TOKEN`. Those inputs are deliberately not
part of the trusted PR interface. It did not provide the candidate binding or
secret-isolation guarantees required here. Inventory consumers before upgrading
their pins; old immutable commits remain accessible in Git history, but the new
entrypoint does not silently retain that weaker mode.

`sonar-dtrack-pr.yml` has been consolidated into this file, not kept as a duplicate
or nested wrapper. Consumer job names and queue groups are preserved. During
migration Vault may temporarily trust the two reviewed exact paths/SHAs; remove
the old binding after all intended target branches use the new entrypoint.

## Validation

```sh
python3 -m unittest discover -s security -p 'test_*.py'
```

Validate the workflows with actionlint and real hosted runs. Older actionlint
schemas need only the narrowly documented `queue` diagnostic ignored, not other
validation disabled. Never merge an unreviewed pin, weaken a quality gate, or
claim branch enforcement solely from a visible workflow/check.

## GitLab generic pipeline (same service/plugin gate, different platform adapter)

`gitlab/dependency-track-scan.yml` is the reusable GitLab template. It uses
`security/gitlab_gate.py` and the existing shared `security_gate.py` service
implementation: runtime-image CycloneDX, DT processing-token completion,
job-time plugin settings reconciliation, then exact-analysis Sonar quality gate.
No alternate CVE threshold, dependency filtering or suppression is introduced.

### Register a repository

1. Register its numeric project ID, exact path, allowed target branches, source/
   test directories and service instance in `security/gitlab_profiles.json`.
2. Provision four distinct canonical Vault records: DT uploader, Sonar project
   analysis token, own-project read-only DT plugin reader and project-settings
   token. Keep the settings account recovery password outside the CI policy.
3. Give the CI policy only those four reads and self-revocation. Create separate
   short-lived GitLab JWT roles for same-project MR events and protected pushes,
   binding issuer/audience/project ID/path/namespace/event; push also binds ref
   and protected branch. Never make inherited static Vault credentials available
   to an unprotected MR. Do not copy another project's service keys.
4. Commit and test the profile/controller, then set the template's literal
   `SECURITY_CONTROL_SHA` to that reviewed code SHA in a second commit. Publish
   both commits before configuring consumers. GitHub consumers keep their own
   immutable pins and are not changed by this addition.
5. Add a reviewed wrapper like `gitlab/prompt-gateway.yml`. Declare stages
   including `test` and `security`, retain required tests, and make publication
   depend on `security`. Any included delivery configuration must also be pinned.
6. Pin GitLab's **project CI configuration setting** to
   `gitlab/<wrapper>.yml@downops/github-workflows:<40-character-template-SHA>`.
   The source `.gitlab-ci.yml` may carry the same include for discoverability,
   but an MR must not control the effective credentialed CI definition.
7. Restrict pipeline-variable overrides to Maintainers. After real CI proof,
   require successful pipelines, reject skipped pipelines and use fast-forward
   merging. The candidate must already contain the current target; a target
   change requires a rebase/new head and a fresh pipeline, not stale green reuse.
   Preserve existing delivery-bot/direct-push controls and document their limits.

### Platform limits and evidence

The existing GitLab Docker executor is privileged and shared by explicit owner
choice. Separate jobs and disposable DinD daemons keep ordinary build scripts
out of the credentialed analysis job, but **do not isolate malicious code from
the runner host or other jobs**. Protected-main jobs may inherit existing protected
delivery variables. Repository writers and runner administrators remain trusted.
No additional runner, VM, host resource change or sandbox equivalence is required
or claimed. Use a stronger executor only as a separately authorized project.

GitLab CE external CI configurations have null `ci_config_ref_uri/ci_config_sha`
JWT claims. Vault does **not** cryptographically bind the external file SHA; the
immutable project CI setting and Maintainer access are the control boundary.
Maintainers able to change that setting or override CI variables are trusted.
CI_JOB_TOKEN repository push must stay disabled. The workflow rejects normal
API/trigger sources; external-status publishing and administrative bypass rights
are NOT independently constrained by this template or tested as a hostile-actor
boundary. Community Sonar snapshot analysis is
serialized by project resource group, not native branch/PR decoration.

The build checks exact source SHA/current target ancestry before and after the
runtime-image build. The scan consumes only bounded BOM+receipt data from its
explicit same-pipeline producer, binding project/pipeline/head/base/target/digest.
It fetches source as static data, ignores source scanner properties, rejects
links/devices, never executes repository helpers with scanner keys, and rechecks
the candidate after analysis. Source/target moves, failed/missing producers,
missing plugin metrics and service/auth errors fail closed. Scanner output is
private; only fixed diagnostics and numeric gate results are logged. Tokens stay
in environment/HTTPS bodies, not argv, URLs, artifacts or Git.

Test a genuine MR gate failure and blocked merge state, an ordinary successful
MR, a changed target, and an MR replacing its local CI file. Lint and unit tests
alone are not proof of GitLab enforcement. Do not merge a vulnerability fixture,
change a shared gate to make a test green or deploy/sign another application.

If GitLab rejects OIDC with `id_token_burned_project_path`, inspect its subject
components. Prompt uses `project_id, ref_type, ref` (no path in `sub`); Vault
still binds the separately signed project path/ID claims. On installed CE19.5.3,
merely prepending ID while retaining a path component did not unblock issuance.
Do not disable global reclaimed-path protection or broaden a Vault role.

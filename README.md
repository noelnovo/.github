# Shared GitHub security workflow

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

Image profiles can declare reviewed `coverage_sources` and trusted Sonar LCOV
settings. The credential-free image build runs real tests and exports
`coverage/lcov.info` through the Dockerfile's `security-coverage` stage. SBOM
and coverage travel in the SAME immutable candidate/run/attempt/digest-verified
artifact. Private analysis accepts only the expected BOM/report files, bounded
regular inputs, exact reviewed source paths present in the fetched candidate,
valid line/count data and all required source records. Only fixed `/app/` path
mapping is allowed; hit counts are never changed. Missing/invalid coverage fails
closed before scanning. No test/build command executes with scanner secrets,
no fabricated report or production-code coverage exclusion is added. Test-only
files are explicitly classified as tests in the reviewed profile.

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

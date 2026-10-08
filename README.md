# .github

Reusable GitHub Actions workflows shared across all products.

## `dependency-track-scan.yml`

Generic, **toolchain-agnostic** reusable workflow (`on: workflow_call`). It does
exactly one thing:

1. downloads an already-generated **CycloneDX** SBOM (a workflow artifact that the
   caller produced),
2. fetches the Dependency-Track secrets from Vault,
3. pushes the SBOM to **OWASP Dependency-Track**,
4. waits until DT finishes analysing it,
5. prints the live DT findings.

It does **not** generate the SBOM — that is toolchain-specific and belongs to each
product's own workflow (Python → Syft, .NET → `cyclonedx-dotnet` / `dotnet CycloneDX`,
Node → `cyclonedx-npm`, Java → `cyclonedx-maven-plugin`, …). Every product just
uploads its SBOM as an artifact and calls this workflow with its name.

Run it **before** the product's SonarQube quality-gate job: SonarQube's
dependency-track plugin proxies the live DT findings at scan time.

### Caller example (in a product repo)

```yaml
  # product-specific: generate the CycloneDX SBOM (swap this for .NET etc.)
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          docker run --rm -v "$(pwd):/workspace" anchore/syft:latest \
            dir:/workspace/app -o cyclonedx-json > bom.json
      - uses: actions/upload-artifact@v4
        with: { name: sbom, path: bom.json }

  # generic: push it to Dependency-Track and wait
  dependency-track:
    needs: [sbom]
    uses: noelnovo/.github/.github/workflows/dependency-track-scan.yml@main
    with:
      sbom-artifact-name: sbom
      vault-secret-path: downops/data/<product>     # e.g. downops/data/wallettracker.backend
    secrets:
      VAULT_TOKEN: ${{ secrets.VAULT_TOKEN }}

  # product-specific: SonarQube runs only after DT finished
  sonarqube:
    needs: [dependency-track]
    runs-on: ubuntu-latest
    steps:
      # ... SonarQube Scan + Quality Gate Check ...
```

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `sbom-artifact-name` | **yes** | — | Name of the workflow artifact containing the CycloneDX SBOM. |
| `sbom-filename` | no | `bom.json` | File name of the SBOM inside the artifact. |
| `vault-secret-path` | **yes** | — | Vault KV path holding `DT_URL` / `DT_API_KEY` / `DT_PROJECT_UUID` (+ optional `NVD_API_KEY`). |
| `vault-url` | no | `https://vault.downops.win` | Vault base URL. |
| `dt-analysis-timeout-attempts` | no | `60` | Poll attempts (×5s) waiting for DT analysis. |
| `runs-on` | no | `ubuntu-latest` | Runner label. |

### Secrets

| Secret | Required | Description |
|---|---|---|
| `VAULT_TOKEN` | **yes** | Vault token used to read `vault-secret-path`. |

### Outputs

| Output | Description |
|---|---|
| `bom-token` | Dependency-Track BOM token for the upload. |

> Cross-repo reusable workflows require this repository to be readable by the
> caller's token, which is why it is public. If it must be private, the caller
> has to use a PAT/app token with read access.

# .github

Reusable GitHub Actions workflows shared across all products.

## `dependency-track-scan.yml`

Generic reusable workflow (`on: workflow_call`) that:

1. fetches the Dependency-Track secrets from Vault (`DT_URL`, `DT_API_KEY`,
   `DT_PROJECT_UUID`, optional `NVD_API_KEY`),
2. generates a **CycloneDX** SBOM with **Syft** from the checked-out source,
3. uploads the SBOM as a workflow artifact,
4. pushes it to **OWASP Dependency-Track** and waits until the DT analysis
   finishes,
5. prints the live DT findings.

It must run **before** the product's SonarQube quality-gate job, because
SonarQube's dependency-track plugin proxies the live DT findings at scan time.

### Caller example (in a product repo)

```yaml
  security-scan:
    needs: [python-tests]
    permissions:
      contents: read
    uses: noelnovo/.github/.github/workflows/dependency-track-scan.yml@main
    with:
      working-directory: app
      vault-secret-path: downops/data/<product>     # e.g. downops/data/wallettracker.backend
    secrets:
      VAULT_TOKEN: ${{ secrets.VAULT_TOKEN }}

  sonarqube:
    needs: [python-tests, security-scan]            # gate runs only after DT is done
    runs-on: ubuntu-latest
    steps:
      # ... checkout, download coverage, SonarQube Scan + Quality Gate Check ...
```

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `working-directory` | no | `.` | Directory whose dependencies are scanned (e.g. `app`). |
| `vault-secret-path` | **yes** | — | Vault KV path holding `DT_URL` / `DT_API_KEY` / `DT_PROJECT_UUID`. |
| `vault-url` | no | `https://vault.downops.win` | Vault base URL. |
| `syft-image` | no | `anchore/syft:latest` | Syft container image. |
| `artifact-name` | no | `sbom` | Name of the uploaded artifact. |
| `upload-artifact` | no | `true` | Upload `bom.json` as an artifact. |
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

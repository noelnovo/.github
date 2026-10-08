# .github

Reusable GitHub Actions workflows shared across all products.

## `dependency-track-scan.yml`

Generic, **toolchain-agnostic** reusable workflow (`on: workflow_call`). It does
exactly one thing:

1. downloads an already-generated **CycloneDX** SBOM (a workflow artifact that the
   caller produced),
2. resolves the Dependency-Track target (explicit inputs/secrets, or Vault),
3. pushes the SBOM to **OWASP Dependency-Track**,
4. waits until DT finishes analysing it,
5. prints the live DT findings.

It does **not** generate the SBOM — that is toolchain-specific and belongs to each
product's own workflow (Python → Syft, .NET → `cyclonedx-dotnet` / `dotnet CycloneDX`,
Node → `cyclonedx-npm`, Java → `cyclonedx-maven-plugin`, …).

Run it **before** the product's SonarQube quality-gate job: SonarQube's
dependency-track plugin proxies the live DT findings at scan time.

### Dependency-Track target (per project)

The workflow is parameterised so one workflow serves many DT projects, each with
its own project UUID and API key:

- explicit `dt-url` input, `dt-project-uuid` input, `DT_API_KEY` secret, **or**
- read from Vault via `vault-secret-path` + `VAULT_TOKEN`.

Explicit values always win, so you can override just the project id and keep the
rest in Vault.

### Caller example — explicit (per project)

```yaml
  dependency-track:
    needs: [sbom]
    uses: noelnovo/.github/.github/workflows/dependency-track-scan.yml@main
    with:
      sbom-artifact-name: sbom
      dt-url: ${{ vars.DT_URL }}
      dt-project-uuid: ${{ vars.DT_PROJECT_UUID }}
    secrets:
      DT_API_KEY: ${{ secrets.DT_API_KEY }}
```

### Caller example — from Vault

```yaml
  dependency-track:
    needs: [sbom]
    uses: noelnovo/.github/.github/workflows/dependency-track-scan.yml@main
    with:
      sbom-artifact-name: sbom
      vault-secret-path: downops/data/<product>
    secrets:
      VAULT_TOKEN: ${{ secrets.VAULT_TOKEN }}
```

### SBOM generation (product-specific)

```yaml
  # Python
  sbom:
    steps:
      - uses: actions/checkout@v4
      - run: docker run --rm -v "$(pwd):/workspace" anchore/syft dir:/workspace/app -o cyclonedx-json > bom.json
      - uses: actions/upload-artifact@v4
        with: { name: sbom, path: bom.json }

  # .NET (same artifact name/filename -> the generic workflow is unchanged)
  # sbom:
  #   steps:
  #     - uses: actions/checkout@v4
  #     - run: dotnet tool install --global CycloneDX && dotnet CycloneDX app/MyApp.csproj -o . -F bom.json
  #     - uses: actions/upload-artifact@v4
  #       with: { name: sbom, path: bom.json }
```

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `sbom-artifact-name` | **yes** | — | Name of the workflow artifact containing the CycloneDX SBOM. |
| `sbom-filename` | no | `bom.json` | File name of the SBOM inside the artifact. |
| `dt-url` | no | `""` | Dependency-Track base URL (overrides Vault). |
| `dt-project-uuid` | no | `""` | Dependency-Track project UUID to upload to (overrides Vault). |
| `vault-url` | no | `https://vault.downops.win` | Vault base URL (Vault mode only). |
| `vault-secret-path` | no | `""` | Vault KV path with `DT_URL` / `DT_PROJECT_UUID` / `DT_API_KEY` (Vault mode). |
| `dt-analysis-timeout-attempts` | no | `60` | Poll attempts (×5s) waiting for DT analysis. |
| `runs-on` | no | `ubuntu-latest` | Runner label. |

### Secrets

| Secret | Required | Description |
|---|---|---|
| `DT_API_KEY` | no | Dependency-Track API key for the target project (overrides Vault). |
| `VAULT_TOKEN` | no | Vault token (Vault mode only). |

> Supply the DT target either explicitly (`dt-url` + `dt-project-uuid` + `DT_API_KEY`)
> or via Vault (`vault-secret-path` + `VAULT_TOKEN`); the workflow errors if it
> cannot resolve URL, project UUID and API key.

### Outputs

| Output | Description |
|---|---|
| `bom-token` | Dependency-Track BOM token for the upload. |

> Cross-repo reusable workflows require this repository to be readable by the
> caller's token, which is why it is public. If it must be private, the caller
> has to use a PAT/app token with read access.

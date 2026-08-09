<div align="center">
  <img src="docs/assets/logo.svg" width="112" alt="VulnFuse shield logo">
  <h1>VulnFuse</h1>
  <p><strong>Stop triaging the same vulnerability three times.</strong></p>
  <p>Local-first, explainable correlation for SARIF, Trivy, Grype, Snyk, CycloneDX, OSV-Scanner, and CSV reports.</p>

[![CI](https://github.com/CAOShurong/vulnfuse/actions/workflows/ci.yml/badge.svg)](https://github.com/CAOShurong/vulnfuse/actions/workflows/ci.yml)
[![CodeQL](https://github.com/CAOShurong/vulnfuse/actions/workflows/codeql.yml/badge.svg)](https://github.com/CAOShurong/vulnfuse/actions/workflows/codeql.yml)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-8cf6c3.svg)](LICENSE)
[![No upload](https://img.shields.io/badge/report_upload-none-8cf6c3.svg)](docs/THREAT_MODEL.md)

[Try the browser workbench](https://caoshurong.github.io/vulnfuse/) · [Why this exists](docs/RESEARCH.md) · [How matching works](docs/MATCHING.md) · [Supported fields](docs/FORMATS.md)
</div>

![VulnFuse browser workbench correlating reports from Trivy, Grype, and Snyk](docs/assets/workbench.png)

Security tools rarely describe the same issue in the same way. One scanner reports a CVE against a package URL, another uses a vendor advisory and an image layer, and a third emits a SARIF rule at a file location. Counting rows inflates the queue; blindly deduplicating them can hide real differences.

VulnFuse converts those reports into one canonical evidence model, scores plausible pairs, blocks unsafe merges, and keeps every source record attached to the resulting cluster. It is a correlation layer—not a scanner, vulnerability database, or false-positive oracle.

## What makes it useful

- **Seven input families, four outputs.** Read SARIF 2.1, Trivy JSON, Grype JSON, Snyk JSON, CycloneDX VDR/VEX, OSV-Scanner JSON, and ordinary CSV. Write VulnFuse JSON, SARIF, CSV, or Markdown.
- **Every merge is reviewable.** Match edges retain the score, confidence, evidence, and exact reasons such as a shared CVE, PURL, asset, location, rule, or scanner fingerprint.
- **Conflicts are first-class.** Explicitly different vulnerability IDs, packages, assets, or finding kinds can block a merge even when titles look similar.
- **Two honest scopes.** `instance` keeps different assets separate. `root-cause` can connect the same vulnerable component across images, repositories, or applications.
- **No report upload.** The hosted workbench runs entirely in the browser. The CLI and Action run in your own environment. No AI, API key, telemetry, or remote correlation service is required.
- **Deterministic output.** Identical input and policy yield stable finding and cluster IDs, which makes diffs and CI review practical.

## Quick start

### Browser

Open the [hosted workbench](https://caoshurong.github.io/vulnfuse/), drop two or more reports, inspect the proposed clusters, and export the result. Choose **Load safe demo** first if you want to explore without using your own data.

### CLI from a release

VulnFuse currently requires Node.js 22.12 or newer. Install the two checksummed v0.1.0 packages directly from the GitHub release:

```bash
npm install --global https://github.com/CAOShurong/vulnfuse/releases/download/v0.1.0/vulnfuse-core-0.1.0.tgz https://github.com/CAOShurong/vulnfuse/releases/download/v0.1.0/vulnfuse-0.1.0.tgz
vulnfuse --version
```

The paired install matters because the CLI and shared core are separate packages. Every release also includes `SHA256SUMS.txt` and a CycloneDX SBOM.

### CLI from source

```bash
git clone https://github.com/CAOShurong/vulnfuse.git
cd vulnfuse
npm ci
npm run build

node packages/cli/dist/index.js merge \
  trivy.json grype.json snyk.json \
  --format markdown \
  --output vulnfuse-report.md
```

Inspect formats before merging:

```bash
node packages/cli/dist/index.js inspect trivy.json grype.json
```

Stream one input and fail CI when a high-severity cluster remains:

```bash
cat osv-results.json | node packages/cli/dist/index.js merge - trivy.json \
  --scope root-cause \
  --format sarif \
  --output vulnfuse-results.sarif \
  --fail-on high
```

Run `node packages/cli/dist/index.js merge --help` for all policy and safety options.

### GitHub Action

The Action accepts paths or newline-separated glob patterns. Generate scanner reports in earlier steps, correlate them, then upload the result as SARIF or retain it as an artifact.

```yaml
- name: Correlate scanner evidence
  id: vulnfuse
  uses: CAOShurong/vulnfuse@v0.1.0
  with:
    reports: |
      reports/trivy.json
      reports/grype.json
      reports/osv.json
    output: reports/vulnfuse.sarif
    format: sarif
    scope: instance
    fail-on: high

- name: Upload correlated SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: reports/vulnfuse.sarif
```

The Action also writes a job summary and exposes `findings`, `clusters`, `duplicates-collapsed`, and `report` outputs.

## Supported input

| Format           | Parsed evidence                                                              | Important boundary                                                             |
| ---------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| SARIF 2.1        | runs, tools, rules, levels, fingerprints, physical/logical locations         | Security severity is used when a rule supplies it                              |
| Trivy JSON       | vulnerabilities, misconfigurations, secrets, packages, image targets, fixes  | Table and template output are not report inputs                                |
| Grype JSON       | matches, artifacts, PURLs, locations, advisories, fixes                      | The JSON schema has changed over time; fixtures cover the current common shape |
| Snyk JSON        | legacy `vulnerabilities`, identifiers, dependency paths, fixes               | Snyk Code SARIF should be supplied as SARIF                                    |
| CycloneDX JSON   | components, vulnerabilities, ratings, affects, analysis/VEX context          | XML BOMs are not parsed yet                                                    |
| OSV-Scanner JSON | sources, packages, aliases, affected ranges, fixed events                    | Scanner output is accepted; arbitrary OSV records need the result wrapper      |
| CSV              | common ID, severity, component, PURL, asset, location, rule, and fix columns | Header aliases are documented in [FORMATS.md](docs/FORMATS.md)                 |

## Matching at a glance

The default threshold is 70. Evidence adds points; incompatible evidence adds hard blockers.

| Evidence                                 |                Score |
| ---------------------------------------- | -------------------: |
| Shared vulnerability identifier          |                  +40 |
| Stable fingerprint from the same scanner |                  +55 |
| Same canonical component or PURL         |                  +25 |
| Same asset                               |                  +15 |
| Same file and nearby line                |           +10 to +15 |
| Same rule ID                             |                  +10 |
| Same finding kind                        |                   +5 |
| Similar meaningful title tokens          | up to +10 by default |

An explicit mismatch is not “negative points”; it can stop the merge. That conservative rule matters because a shared package does not make two different CVEs the same vulnerability. See [MATCHING.md](docs/MATCHING.md) for the complete policy, candidate indexing, confidence labels, and examples.

## Repository layout

```text
packages/core    canonical model, parsers, matching, correlation, exporters
packages/cli     Node.js command-line interface
packages/action  bundled Node 24 GitHub Action
apps/web         local-only React/Vite workbench deployed to GitHub Pages
docs             format contract, algorithm, architecture, and threat model
```

## Security and data handling

Scanner reports can contain repository paths, package inventories, hostnames, code locations, and sometimes secret fragments. Treat them as sensitive.

- The hosted app has no upload endpoint and makes no API call to process a report.
- File size, report count, pair-comparison, output overwrite, symlink traversal, URL scheme, and CSV formula-injection safeguards are built in.
- Uploaded strings are rendered as React text, not injected HTML.
- A correlation result does **not** prove that a vulnerability is exploitable, reachable, fixed, or a false positive.

Read [THREAT_MODEL.md](docs/THREAT_MODEL.md) before using untrusted reports in automation. Report suspected vulnerabilities through the private process in [SECURITY.md](SECURITY.md).

## Project status

`v0.1.0` is an initial public alpha. The core behavior is covered by synthetic cross-format fixtures and end-to-end CLI/browser checks, but real vendor output varies by scanner version. Please open a sanitized [format compatibility issue](https://github.com/CAOShurong/vulnfuse/issues/new?template=format.yml) when a legitimate report is not parsed correctly.

Near-term work:

- Add scanner-version fixtures contributed by users.
- Add CycloneDX XML and SPDX vulnerability extensions where a stable mapping exists.
- Publish signed npm packages after the package-distribution lifecycle is verified.
- Add policy files for organization-specific asset and component aliases.
- Benchmark very large monorepo and container-report sets.

## Contributing

The most useful contribution is a small, sanitized report fixture with the expected canonical fields. Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting data; never attach proprietary inventories, tokens, or live secrets.

Apache-2.0 licensed. Built to complement scanners and vulnerability-management systems, not replace them.

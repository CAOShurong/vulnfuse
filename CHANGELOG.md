# Changelog

All notable changes to VulnFuse are documented here. The project follows semantic versioning after the initial alpha boundary.

## [Unreleased]

## [0.4.1] - 2026-08-09

### Fixed

- Attribute report and source-finding counts to every actual scanner in mixed-tool CSV and multi-run SARIF inputs instead of assigning the whole file to its first tool.
- Preserve tools declared by empty SARIF runs so zero-finding scans remain visible in coverage comparisons.
- Record actual Trivy and CycloneDX producer versions as scanner evidence while keeping report schema/specification versions in metadata.

### Changed

- Add a sorted `tools` list to every report summary while retaining the existing primary `tool` field for compatibility.

## [0.4.0] - 2026-08-09

### Added

- Deterministic scanner-coverage analytics with per-tool report, finding, cluster, exclusive, and shared counts.
- Pairwise shared/union cluster counts and Jaccard overlap in canonical JSON, Markdown, portable HTML, the browser workbench, and GitHub Action summaries.
- Scanner and one-tool/multi-tool filters in both interactive review surfaces.
- `single-tool` and `multi-tool` GitHub Action outputs for downstream workflow policy.

### Safety

- Describe overlap as evidence coverage rather than a correctness vote; a one-tool cluster is not automatically a false positive.
- Omit quadratic pairwise rows above 20 tools while retaining complete per-tool coverage statistics.

## [0.3.0] - 2026-08-09

### Added

- Self-contained interactive HTML reports for plain correlations and baseline comparisons in the core, CLI, GitHub Action, and browser workbench.
- Offline search plus severity, baseline-state, and asset filters; expandable evidence, blockers, source records, and safe advisory links.
- CLI and Action end-to-end coverage for portable HTML output, plus manual Edge visual and interaction checks.

### Security

- Contextually escape all report-controlled HTML text and attributes, refuse non-HTTP(S) references, and keep report data out of the inline script and style blocks.
- Ship a restrictive Content Security Policy and no external fonts, scripts, styles, images, analytics, or network requests.

## [0.2.0] - 2026-08-09

### Added

- Deterministic comparison of independently correlated baseline and current reports with `new`, `updated`, `unchanged`, and `absent` states.
- CLI `diff` command with repeatable baseline inputs, four output formats, atomic writes, and `--fail-on-new` severity gates.
- GitHub Action baseline globs, new-only failure policy, baseline counts, and a baseline-aware job summary.
- Browser workbench baseline picker, state summaries, cluster badges, evidence changes, and comparison downloads without report upload.

### Changed

- SARIF exports now include stable `partialFingerprints.primaryLocationLineHash` values; baseline SARIF includes the standard `baselineState` field on every result.
- Research, architecture, matching, input/output, threat-model, and usage documentation now cover cross-run evidence.

## [0.1.1] - 2026-08-09

### Security

- Replaced trailing identifier punctuation cleanup with a linear scan to avoid pathological regular-expression work on attacker-controlled reports.
- Render Markdown component values with delimiter-aware code spans so embedded backticks and backslashes cannot break the report structure.
- Excluded the generated Action bundle from duplicate CodeQL analysis while retaining source analysis, dependency audit, and bundle-drift verification.

### Changed

- Added a verified direct-from-release CLI installation path.
- Deferred TypeScript major updates until the `typescript-eslint` peer range supports them.

## [0.1.0] - 2026-08-09

### Added

- Canonical finding and correlation-result schemas.
- Parsers for SARIF 2.1, Trivy, Grype, Snyk, CycloneDX JSON, OSV-Scanner JSON, CSV, and VulnFuse JSON.
- Deterministic scoring, blockers, instance/root-cause scope, candidate indexing, stable IDs, and rejected-candidate evidence.
- JSON, SARIF, CSV, and Markdown exporters.
- Node.js CLI with stdin, bounded reads, atomic output, inspection, and severity exit codes.
- Node 24 GitHub Action with bounded glob input, job summary, and outputs.
- Local-only browser workbench with safe synthetic demo and multi-format downloads.
- CI, CodeQL, Pages deployment, dependency updates, security policy, threat model, and contribution guidance.

[Unreleased]: https://github.com/CAOShurong/vulnfuse/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.1
[0.4.0]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.0
[0.3.0]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.3.0
[0.2.0]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.2.0
[0.1.1]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.1.1
[0.1.0]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.1.0

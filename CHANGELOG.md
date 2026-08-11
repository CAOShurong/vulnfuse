# Changelog

All notable changes to VulnFuse are documented here. The project follows semantic versioning after the initial alpha boundary.

## [Unreleased]

## [0.4.14] - 2026-08-12

### Fixed

- Resolve valid relative `artifactLocation.uriBaseId` chains from SARIF
  `run.originalUriBaseIds` before file assets and locations enter correlation.
  A scanner path such as `lib/memory.c` under `SRCROOT = src/` can now match
  another scanner's direct `src/lib/memory.c` path.
- Preserve the original relative URI, URI-base id, and resolution boundary as
  source evidence when VulnFuse adds a portable prefix.
- Warn and retain the unmodified finding when a referenced base is unknown,
  circular, malformed, unsafe, or deeper than the bounded resolution limit.
- Make repository checks fail when the CLI, HTML generator, or SARIF exporters
  embed a version different from the workspace manifests.

### Safety

- Omit producer-specific absolute roots from canonical paths instead of
  exporting usernames or machine layouts. Resolution only prepends validated
  relative segments already embedded in the report.
- Reject URI-base segments with queries, fragments, backslashes, malformed
  percent encoding, or `..` traversal; add no dependency, file access, network
  request, or source-root guess.

### Limitations

- This is portable repository-relative correlation, not complete SARIF URI
  resolution or source-file navigation. VulnFuse does not accept user URI-base
  mappings, reconstruct a redacted absolute root, resolve symlinks, or prove
  that two producer path conventions name the same checkout.

## [0.4.13] - 2026-08-12

### Added

- Detect SARIF's documented incomplete-result signals: unsuccessful or
  malformed invocations, error-level tool/configuration notifications, and
  unavailable, invalid, or externally referenced result arrays.
- Add opt-in CLI and Action `fail-on-incomplete` gates that retain partial
  findings, finish the selected export, and then return failure.
- Expose the Action `incomplete-reports` count, retain per-run health metadata,
  and carry source report warnings through correlation, baseline JSON, and
  SARIF invocation properties.

### Safety

- Preserve every available inline finding instead of rejecting a partial run;
  warnings identify uncertainty without turning producer failure metadata into
  a vulnerability disposition.
- Add no runtime dependency, make no external-property request, and never
  execute a SARIF-recorded command line.

### Limitations

- VulnFuse does not perform full SARIF schema validation, retrieve external
  property files, prove which targets or rules ran, or infer that missing
  run-health metadata means a scan was complete.

## [0.4.12] - 2026-08-12

### Added

- Detect and parse standalone OpenVEX JSON-LD documents across the core
  library, CLI, browser workbench, and bundled GitHub Action.
- Expand every product and listed subcomponent into attributable canonical
  evidence, using valid PURLs for component identity and retaining the parent
  product as asset scope.
- Preserve vulnerability aliases, document author and timestamps, status,
  justification, impact/action statements, identifiers, hashes, and raw product
  or subcomponent records.

### Safety

- Keep every OpenVEX statement active for correlation and gates. Producer
  `not_affected` and `fixed` labels are evidence, not authenticated suppression
  or non-finding verdicts.
- Warn on invalid status/PURL fields, incomplete status requirements, and
  absent in-document products instead of guessing an identity or granting a
  quiet gate bypass.
- Add no runtime dependency and make no context, discovery, or attestation
  network request.

### Limitations

- VulnFuse does not unwrap or verify DSSE/in-toto attestations, authenticate the
  author, inherit products from an encapsulating document, apply version-range
  matching, or prove exploitability, reachability, remediation, or safety.

## [0.4.11] - 2026-08-11

### Fixed

- Expand every CycloneDX `vulnerabilities[].affects[]` target into its own
  canonical finding instead of silently keeping only the first affected
  component.
- Recover a component PURL when an affected reference is either a valid PURL
  itself or a valid CycloneDX BOM-Link element whose fragment is a valid PURL.
  External VEX evidence can now correlate with another scanner's report of the
  same CVE/package rather than remaining an unidentified singleton.

### Safety

- Require the full BOM-Link element syntax and validate the fragment with the
  existing `packageurl-js` parser. Arbitrary external `bom-ref` fragments stay
  unresolved and visible instead of being guessed into package identities.
- Preserve the complete source `affects` and VEX analysis as properties; the
  parser still does not reinterpret producer-declared VEX state as proof of
  exploitability, suppression, or a false positive.

### Limitations

- VulnFuse does not retrieve the referenced external BOM or resolve arbitrary
  BOM-Link fragments. A non-PURL fragment needs the referenced inventory to
  establish component identity and therefore remains uncorrelated unless
  another supported field supplies that evidence.

## [0.4.10] - 2026-08-11

### Added

- Preserve SARIF `result.kind` and distinguish valid `pass`, `informational`, and `notApplicable` records as non-finding evidence instead of active vulnerabilities.
- Report non-finding cluster counts and disposition across JSON, CSV, Markdown, portable HTML, the browser workbench, CLI inspection, and GitHub Action outputs.
- Retain non-finding clusters in VulnFuse SARIF `run.properties` while omitting them from `results[]`, because GitHub code scanning does not document `result.kind` in its supported SARIF subset.

### Changed

- Apply `--fail-on`, `--fail-on-new`, and their Action equivalents only to active clusters. Fully non-finding clusters remain reviewable but do not fail severity gates.
- Prefer active evidence, then effectively suppressed evidence, then non-finding evidence when selecting a cluster's primary record. An active corroborating record always keeps the cluster active.
- Treat result disposition changes as significant baseline updates.

### Safety

- Keep unknown, non-string, or contradictory `result.kind` and `level` combinations active and emit a targeted warning instead of allowing ambiguous metadata to bypass a gate.

### Limitations

- `result.kind` is producer-declared metadata. VulnFuse does not rerun the rule, prove that a check passed, or establish that a rule was applicable to the target.

## [0.4.9] - 2026-08-11

### Added

- Preserve SARIF `result.suppressions` kind, status, and justification in the canonical model and every review/export surface.
- Report total, active, and effectively suppressed cluster counts, including separate per-severity summaries and GitHub Action outputs.
- Add suppression filters and source justification details to the browser workbench and self-contained HTML report.

### Changed

- Apply `--fail-on`, `--fail-on-new`, and their Action equivalents to active clusters only. A cluster remains active when any source record is active, contested, or malformed.
- Record active-to-suppressed baseline transitions as updated evidence and preserve suppression state in CSV, Markdown, SARIF, and HTML diffs.

### Safety

- Treat unknown suppression containers, objects, kinds, or statuses as active and emit `sarif.invalid-suppression` instead of allowing an ambiguous gate bypass.

### Limitations

- Suppression is producer-declared metadata. VulnFuse does not authenticate the producer, validate a risk-acceptance decision, prove a finding false, or mutate hosted alert state.

## [0.4.8] - 2026-08-11

### Added

- Record added/removed scanner tools and changed per-tool report counts in every baseline comparison.
- Surface scan-set drift in JSON, row-bearing CSV, Markdown, SARIF invocation properties, portable HTML, the browser workbench, CLI stderr, and the GitHub Action summary/log.
- Add opt-in CLI `--fail-on-scan-set-change` and Action `fail-on-scan-set-change` gates that preserve the complete comparison before returning failure.
- Expose the Action `scan-set-changed` output for downstream workflow decisions.

### Fixed

- Disable Zod's optional JIT schema compilation so the hosted workbench does not trigger a blocked `eval` probe under its strict content security policy.

### Limitations

- Matching tool names and report counts do not prove identical assets, scan configuration, scanner versions, rule sets, or vulnerability databases. The drift signal is a comparability warning, not a scientific validity claim.

## [0.4.7] - 2026-08-11

### Added

- Expand quoted report globs inside the CLI for shell-independent `merge`, `diff`, `inspect`, and single-match `detect` workflows.
- Treat existing paths as literal before glob interpretation, deduplicate overlapping paths/patterns, and sort each pattern's matches deterministically.

### Safety

- Match files only, do not traverse symbolic-link directories, fail on unmatched patterns, and enforce the 1,000-report limit after expansion.
- Verify that release SBOMs contain their expected runtime components instead of trusting a syntactically valid but incomplete workspace inventory.

### Fixed

- Generate the CLI/core release SBOM from a fresh installation of the exact packed archives, so it includes transitive runtime dependencies such as `tinyglobby`, `fdir`, and `picomatch`.
- Publish a separate Action runtime SBOM instead of combining two materially different installation surfaces into an ambiguous inventory.

### Dependencies

- Add MIT-licensed `tinyglobby` 0.2.17 to the CLI only; the core, browser, and GitHub Action dependency surfaces are unchanged.

## [0.4.6] - 2026-08-11

### Fixed

- Write GitHub Action reports through the same temporary-sibling-and-rename path as the CLI so a caught partial-write failure does not replace a previously complete report.
- Flush a unique, exclusively created temporary file before replacement and remove it when a write or rename reports an error.

### Changed

- Share the dependency-free Node output writer through `@vulnfuse/core/node`; no new runtime package or service is required.

## [0.4.5] - 2026-08-11

### Fixed

- Reject files whose known size exceeds `--max-bytes` before reading their contents in the CLI and GitHub Action.
- Bound incremental reads to at most the configured limit plus one observed byte so file growth and metadata races cannot bypass the check.
- Close the file handle on success, size rejection, incremental overflow, and read failure.
- Clean each workspace `dist` before building so repeated local builds cannot leave deleted-source artifacts in release packages.

### Added

- Add a Node-only `@vulnfuse/core/node` entry point so the CLI and Action share one dependency-free bounded-read implementation without pulling Node APIs into the browser entry point.

## [0.4.4] - 2026-08-11

### Fixed

- Print runtime and report-input failures as one concise `vulnfuse: <message>` diagnostic instead of an unhandled Node.js stack trace.
- Preserve exit code 1, clean stdout, output-file safety, and the existing report-before-policy-exit behavior.

### Added

- Add an explicit global `--debug` option for full runtime stacks when diagnosing a failure; debug output may contain local paths.

## [0.4.3] - 2026-08-11

### Fixed

- Prevent a chain of individually matched pairs from merging two findings that have a direct identifier, component, asset, or kind blocker.
- Process candidate matches by strongest evidence and stable finding IDs so the safe partition does not depend on report order.
- Preserve the blocking member pair as rejected evidence and fail visibly above one million cluster-safety comparisons.

## [0.4.2] - 2026-08-09

### Fixed

- Accept JSON reports with a leading UTF-8 byte-order mark, including files and standard input produced by common Windows PowerShell workflows.

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

[Unreleased]: https://github.com/CAOShurong/vulnfuse/compare/v0.4.14...HEAD
[0.4.14]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.14
[0.4.13]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.13
[0.4.12]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.12
[0.4.11]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.11
[0.4.10]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.10
[0.4.9]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.9
[0.4.8]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.8
[0.4.7]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.7
[0.4.6]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.6
[0.4.5]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.5
[0.4.4]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.4
[0.4.3]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.3
[0.4.2]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.2
[0.4.1]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.1
[0.4.0]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.4.0
[0.3.0]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.3.0
[0.2.0]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.2.0
[0.1.1]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.1.1
[0.1.0]: https://github.com/CAOShurong/vulnfuse/releases/tag/v0.1.0

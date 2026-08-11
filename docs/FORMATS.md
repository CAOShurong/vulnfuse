# Input format contract

VulnFuse normalizes scanner reports into one canonical finding model. Parsers are intentionally defensive: missing optional fields become unknown evidence, while malformed documents or unsupported shapes fail with a clear error.

All JSON inputs must contain an object. A leading UTF-8 byte-order mark is accepted for compatibility with Windows-generated files and standard input. CycloneDX XML is the one non-JSON structured format; generic JSON arrays are not supported in v0.4.x.

## Canonical finding

Each source record can supply:

- source tool, version, report name, and run;
- finding kind and severity;
- title and description;
- vulnerability, weakness, alias, and rule identifiers;
- component PURL, ecosystem, name, version, path, and type;
- asset type and key;
- file URI, line, column, and symbol;
- scanner fingerprints;
- fixed version and recommendation;
- safe HTTP(S) references;
- producer-declared suppression kind, status, and justification;
- producer-declared SARIF result kind and non-finding disposition;
- format-specific JSON properties.

Missing evidence is not fabricated. For example, a CVSS score is not inferred when a report contains only a severity word.

The CLI and GitHub Action assign a portable source-report label before parsing.
Files under the CLI working directory or `GITHUB_WORKSPACE` use a forward-slash
relative label. Outside-root inputs use `external-report/<basename>`; duplicate
basenames receive an ordinal in sorted input order. The label is preserved in
source evidence and participates in stable finding identity, while the actual
filesystem path is kept only for reading and local diagnostics. This does not
remove absolute paths already supplied inside scanner fields. A label that was
absolute in v0.4.22 or earlier changes once after upgrading.

## SARIF 2.1

VulnFuse reads:

- `runs[].tool.driver` name, `semanticVersion` (falling back to `version`), rules, descriptions, tags, and `security-severity`;
- `runs[].invocations[]` boolean execution status plus error-level tool and configuration notifications;
- `results[]` rule ID, kind, level, message, properties, fingerprints, partial fingerprints, and references;
- first physical and logical location, including URI, region, and fully qualified symbol.

SARIF results default to `sast`; rule tags can classify SCA, container, IaC, secret, DAST, or license findings. A rule's numeric `security-severity` takes precedence over SARIF's diagnostic `level`.

SARIF `result.kind` defaults to `fail` when omitted. Valid `pass`, `informational`, and `notApplicable` values become non-finding evidence when `level` is `none` or omitted. `fail`, `open`, and `review` remain active. An unknown or non-string kind emits `sarif.invalid-result-kind`; a non-fail kind paired with an explicit level other than `none` emits `sarif.inconsistent-result-kind`. Both conservative failure cases preserve the raw value under `properties["sarif.resultKind"]` and remain gate-eligible.

SARIF run completeness is independent of finding disposition. VulnFuse emits targeted warnings when an invocation declares `executionSuccessful: false`, omits a valid boolean execution status, contains an error-level tool/configuration notification, or is malformed. A null, absent, invalid, or externally referenced `results` value also warns because external property files are not fetched. Available inline results are still parsed and correlated. CLI/Action `fail-on-incomplete` is opt-in and applies only after requested output is written; a missing warning does not prove that the producer scanned every intended target and rule.

When a result's relative `artifactLocation.uri` names a `uriBaseId`, VulnFuse follows `run.originalUriBaseIds` and prepends each validated relative URI segment. Resolution stops at a top-level entry whose absolute URI was omitted/redacted or whose URI is absolute; that absolute root is deliberately not copied into canonical file identity. The original relative URI, base id, and resolution boundary remain under `properties["sarif.*"]` when a prefix changes the path. Unknown or circular bases and entries with invalid types, missing parents, queries, fragments, backslashes, malformed percent encoding, or `..` segments emit a targeted warning and preserve the raw location. Chains are bounded to 100 entries.

This is a portable correlation policy, not full SARIF URI navigation. VulnFuse does not accept a configured base mapping, infer a local source root, resolve a redacted absolute directory, open the referenced file, or resolve symlinks. If the only declared base is absolute, the relative artifact URI remains unchanged because no portable prefix is established.

VulnFuse also reads `results[].suppressions`. An absent, `null`, or empty list is active. A non-empty valid list is effectively suppressed when every entry has status `accepted` or omits status. If any entry is `underReview` or `rejected`, the result remains active. An unrecognized container, object, kind, or status emits `sarif.invalid-suppression` and keeps the result active rather than granting a quiet gate bypass. Kinds are limited to SARIF's `inSource` and `external` values.

Correlation keeps every source record and computes one of three cluster dispositions. A cluster is non-finding only when every member is non-finding. Otherwise, it is effectively suppressed only when every actual-finding member is effectively suppressed. Any active actual-finding member keeps the whole cluster active. Primary-record selection follows the same precedence: active, then effectively suppressed, then non-finding evidence.

Disposition appears in JSON, CSV, Markdown, portable HTML, the browser, CLI gates, and Action outputs. A fully suppressed cluster gets `result.suppressions` in SARIF export; mixed active clusters retain per-source suppression evidence under VulnFuse result properties. GitHub code scanning does not document `result.kind` in its supported SARIF subset and treats uploaded results as alerts, so VulnFuse deliberately omits non-finding clusters from exported `results[]` and preserves them under `run.properties.nonFindingClusters` (or `nonFindingItems` for a baseline export). This avoids creating hosted alerts for producer-declared pass/not-applicable outcomes while retaining their audit data in the file.

## Trivy JSON

VulnFuse reads the standard JSON report shape with `Results[]` and supports:

- `Vulnerabilities[]`, package identifiers/PURLs, installed and fixed versions, status, CVSS, layer digest, and references;
- `Misconfigurations[]`, rule IDs, cause metadata, file target, severity, and references;
- `Secrets[]`, category, rule, match fingerprint, line range, and severity;
- artifact name/type and result target/class/type.

Use `trivy ... --format json --output trivy.json`. Human-readable tables and custom template output are not accepted.

## Grype JSON

VulnFuse reads `matches[]` with vulnerability, artifact, match-detail, source, and descriptor records. It recognizes PURLs, artifact IDs, image targets, package locations, advisory aliases, CVSS data, URLs, and fixed versions.

## Snyk JSON

The parser supports the common legacy Open Source shape with top-level `vulnerabilities[]`, plus `issues.vulnerabilities[]` when present. It reads identifier maps, package manager/name/version/PURL, dependency path, target file, fix versions, upgrade metadata, references, and project name.

Snyk Code findings should be exported as SARIF. If Snyk changes its JSON contract, attach a sanitized fixture to a format issue.

## CycloneDX JSON and XML

VulnFuse reads CycloneDX JSON BOMs whose `bomFormat` is `CycloneDX` and XML BOMs whose `bom` root declares a `http://cyclonedx.org/schema/bom/1.x` or HTTPS-equivalent namespace. Both serializations feed the same supported-field parser, including:

- component `bom-ref`, PURL, group, name, version, and type;
- vulnerability ID, source, ratings, CWE values, description, recommendation, references, advisories, and analysis;
- every `affects[]` target and its version/status entries;
- direct PURL affected references and PURL fragments inside valid CycloneDX
  BOM-Link element references, including external VEX documents;
- metadata root component and producing tool.

Each affected target becomes a separate canonical finding. A matching local
component supplies its identity first; when no component PURL exists, a direct
PURL reference or a PURL in a syntactically valid BOM-Link element fragment is
validated with `packageurl-js` and used as package identity. An arbitrary
external fragment is retained but not guessed, because resolving it requires
the referenced BOM. An `unaffected` version in an affected record is exposed
as a fixed-version candidate. The complete source `affects` array and VEX
analysis remain in properties; VulnFuse does not convert VEX state into a
false-positive verdict or retrieve external BOMs.

XML support is a bounded field mapping, not complete schema validation or a
lossless serialization converter. It rejects every `DOCTYPE`, does not resolve
custom or external entities, fetch schemas, process signatures, or interpret
foreign namespace extensions. Malformed XML fails with a concise input error.
Element nesting is limited to 100. The parser is non-streaming, so the input
text and parsed tree both count toward runtime memory even though the existing
per-report byte limit is enforced.

## OpenVEX JSON-LD

VulnFuse detects standalone OpenVEX documents whose `@context` names an
`https://openvex.dev/ns/v...` context. It reads document author, role,
timestamp, update time, version, tooling, and ID, plus statement:

- vulnerability name, aliases, description, and reference IRI;
- every product and every listed subcomponent;
- PURL identifiers from `identifiers.purl` or a PURL-valued `@id`;
- status, justification, status notes, impact statement, action statement,
  timestamps, hashes, and other source component fields.

When a product lists subcomponents, each subcomponent becomes a separate
canonical finding and the parent product remains its asset scope. Without
subcomponents, the product itself supplies component identity. Valid PURLs are
canonicalized with `packageurl-js`; arbitrary IRIs and hashes stay preserved in
format-specific properties but are not guessed into package identities.

OpenVEX status is producer-supplied evidence. `not_affected`, `affected`,
`fixed`, and `under_investigation` are preserved under
`properties["openvex.status"]`, but none is converted into VulnFuse suppression
or non-finding state. Invalid status, invalid declared PURLs, incomplete
`not_affected`/`affected` statements, and missing in-document products emit
targeted warnings and cannot create a silent gate bypass.

The parser does not fetch JSON-LD contexts, inherit products from an
encapsulating document, unwrap DSSE/in-toto attestations, verify signatures,
authenticate authors, apply version-range matching, or prove reachability or
exploitability. Supply the standalone OpenVEX predicate as JSON when the source
is an attestation, and validate its provenance separately.

## OSV-Scanner JSON

VulnFuse reads `results[].source` and `results[].packages[]`, including package name, ecosystem, version, PURL, vulnerability ID, aliases, summary, details, references, severity metadata, affected ranges, and `fixed` events.

The parser expects the scanner result wrapper, not a single raw OSV database record.

## CSV

CSV requires a header row. Header matching is case-insensitive and trims whitespace. At least one title-like or ID-like value must exist for a row to become a finding.

| Canonical field   | Recognized headers                                           |
| ----------------- | ------------------------------------------------------------ |
| Vulnerability ID  | `vulnerability_id`, `vulnerability`, `id`, `cve`, `advisory` |
| Title             | `title`, `summary`, `name`                                   |
| Description       | `description`, `details`                                     |
| Severity          | `severity`, `priority`, `cvss`, `score`                      |
| Kind              | `kind`, `category`, `type`                                   |
| Component         | `component`, `package`, `package_name`, `dependency`         |
| Component version | `version`, `installed_version`, `component_version`          |
| PURL              | `purl`, `package_url`                                        |
| Ecosystem         | `ecosystem`, `package_manager`                               |
| Asset             | `asset`, `target`, `repository`, `image`, `host`             |
| Location          | `path`, `file`, `uri`, `location`                            |
| Start line        | `line`, `start_line`, `startline`                            |
| Rule              | `rule_id`, `rule`, `check_id`                                |
| Fingerprint       | `fingerprint`, `hash`, `finding_id`                          |
| Fixed version     | `fixed_version`, `fixedin`, `fix_version`                    |
| Recommendation    | `recommendation`, `remediation`, `fix`                       |
| References        | `references`, `reference`, `url`                             |
| Tool              | `tool`, `scanner`, `source`                                  |
| Tool version      | `tool_version`, `scanner_version`                            |

CSV references can be separated by whitespace, commas, or semicolons. Only HTTP(S) references survive normalization. CSV export prefixes spreadsheet-formula cells defensively.

## VulnFuse JSON

Canonical VulnFuse JSON can be supplied again as input. Valid cluster members are flattened into source findings and correlated under the new policy. Invalid members produce warnings rather than being silently accepted.

## Output contracts

A plain correlation exports the complete `CorrelationResult`. A baseline comparison exports a `BaselineDiffResult` containing baseline/current report summaries and warnings, correlation summaries, a structured `scanSetChange`, and one item per `new`, `updated`, `unchanged`, or `absent` cluster. JSON preserves full evidence; each emitted CSV finding row repeats the scan-set warning plus `baseline_state` and changed fields, while an empty CSV has only its header; Markdown focuses on changes; SARIF writes `baselineState` on every result, a stable `primaryLocationLineHash` partial fingerprint, and source-report health plus scan-set structure in invocation properties.

Each SARIF rule emits at most nine hosted-facing `properties.tags` values: `security`, the finding kind, then up to seven identifiers ordered by relationship priority and identifier value. If more identifiers exist, `vulnfuseOmittedIdentifierTagCount` records how many were not copied into tags; the complete structured identifier array remains under the corresponding result's VulnFuse properties. The same builder is used by plain and baseline-comparison SARIF.

Rule names are limited to 255 UTF-16 code units; rule short/full descriptions and result messages are limited to 1,024. Truncation reserves one code unit for an ellipsis and iterates complete Unicode code points, so it cannot leave half of a surrogate pair. Exact over-limit values are retained in `vulnfuseOriginalName`, `vulnfuseOriginalShortDescription`, `vulnfuseOriginalFullDescription`, and `vulnfuseOriginalMessage`; `vulnfuseTruncatedFields` names the shortened rule fields. Hosted products can ignore custom properties, so their rule filters and alert titles are not a complete evidence view. The bounds cover documented GitHub/GitLab fields, not every platform-specific compatibility rule.

Plain and baseline SARIF exporters accept an optional fallback location. It is
attached at line 1 only when a result has no physical URI and is marked by
`vulnfuseLocationProvenance: user-supplied-fallback`; an existing source URI
and region always win. The value must be a non-empty forward-slash
repository-relative URI without a scheme, traversal, empty segments, query,
fragment, whitespace, control characters, invalid percent encoding, or encoded
separators. Validation is syntactic: VulnFuse does not open the file, prove that
it exists in a commit, or claim that the selected file caused the result.

Every report summary has a primary `tool` plus a sorted `tools` list, a `toolVersions` map, and a `sarifAutomationCategories` map. The tool list records every producer represented by a mixed CSV file or multi-run SARIF document, including declared SARIF runs with zero findings. Version sets are trimmed, deduplicated, and sorted as opaque strings; they are not ordered or interpreted as upgrades. For each SARIF tool, category evidence records sorted GitHub-style category prefixes and the number of runs with no category. The identifier is preserved as evidence only: VulnFuse does not infer actual files, languages, scope, or hierarchy from it.

Every correlation summary includes total, active, and effectively suppressed cluster counts and per-severity counts, plus a deterministic `coverage` object. Its per-tool rows count input reports, source findings attributed to that tool, resulting clusters, clusters reported only by that tool, and clusters shared with another tool. Pair rows record the shared cluster count, the union count, and Jaccard overlap (`shared / union`). Pairwise rows are omitted when more than 20 distinct tools are present to bound quadratic output; complete per-tool counts remain available. These values describe attribution and overlap, not scanner accuracy, false-positive rate, or majority truth.

Scanner versions come from producer-specific fields: SARIF `tool.driver.semanticVersion` with `version` as its fallback, Grype `descriptor.version`, Trivy `Trivy.Version` when present, the first supported CycloneDX `metadata.tools` producer, and CSV `tool_version`/`scanner_version`. Report schema versions such as SARIF's top-level `version`, Trivy `SchemaVersion`, and CycloneDX `specVersion` remain metadata and are not presented as scanner versions. Many legitimate reports omit producer versions; VulnFuse reports that absence and never guesses from a filename, command log, package registry, or current release.

HTML is a self-contained review surface rather than a machine-ingestion format. It embeds no report JSON and loads no remote assets. All report-controlled text and attributes are escaped before rendering; its fixed inline script only filters and expands already-rendered findings. The file supports search and severity, baseline-state, asset, scanner, one-tool/multi-tool, and three-state disposition filters while retaining match evidence, blockers, source result kinds, suppression justifications, and safe HTTP(S) references.

Baseline comparison output is an audit artifact, not a raw scanner input. Supply the previous raw reports or a plain VulnFuse correlation JSON when constructing the next baseline.

## Compatibility smoke checks

The deterministic test suite uses small synthetic fixtures so edge cases stay reviewable. Before the v0.1.0 release, the CLI was also smoke-tested against two public, independently maintained report files without copying them into this repository:

- Trivy's [`alpine-39.json.golden`](https://github.com/aquasecurity/trivy/blob/main/integration/testdata/alpine-39.json.golden) integration fixture: detected as Trivy and parsed six findings without warnings.
- DefectDojo's [`fix_available.json`](https://github.com/DefectDojo/django-DefectDojo/blob/master/unittests/scans/anchore_grype/fix_available.json) Grype fixture: detected as Grype and parsed one finding without warnings.

These are narrow compatibility checks, not a claim that every historical scanner version or field variant is covered.

## Severity mapping

VulnFuse normalizes common labels and numeric scores:

- `critical`, `blocker`, `error`, or score ≥9 → critical;
- `high`, `important`, or score ≥7 → high;
- `medium`, `moderate`, `warning`, or score ≥4 → medium;
- `low`, `minor`, `note`, or score >0 → low;
- `info`, `none`, `negligible`, or score 0 → info;
- anything else → unknown.

This is a presentation normalization, not a CVSS calculation.

## Supplying a compatibility fixture

Remove organization names, repository paths, image registries, hostnames, proprietary packages, source fragments, and credentials. Replace them with deterministic synthetic values while preserving the report structure that triggers the problem. Explain the scanner version, command family, expected finding count, and fields that should map.

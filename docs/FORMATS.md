# Input format contract

VulnFuse normalizes scanner reports into one canonical finding model. Parsers are intentionally defensive: missing optional fields become unknown evidence, while malformed documents or unsupported shapes fail with a clear error.

All JSON inputs must contain an object. A leading UTF-8 byte-order mark is accepted for compatibility with Windows-generated files and standard input. CycloneDX XML and generic arrays are not supported in v0.4.x.

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
- format-specific JSON properties.

Missing evidence is not fabricated. For example, a CVSS score is not inferred when a report contains only a severity word.

## SARIF 2.1

VulnFuse reads:

- `runs[].tool.driver` name, version, rules, descriptions, tags, and `security-severity`;
- `results[]` rule ID, level, message, properties, fingerprints, partial fingerprints, and references;
- first physical and logical location, including URI, region, and fully qualified symbol.

SARIF results default to `sast`; rule tags can classify SCA, container, IaC, secret, DAST, or license findings. A rule's numeric `security-severity` takes precedence over SARIF's diagnostic `level`.

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

## CycloneDX JSON

VulnFuse reads CycloneDX JSON BOMs whose `bomFormat` is `CycloneDX`, including:

- component `bom-ref`, PURL, group, name, version, and type;
- vulnerability ID, source, ratings, CWE values, description, recommendation, references, advisories, and analysis;
- `affects[].ref` and version/status entries;
- metadata root component and producing tool.

An `unaffected` version in the first affected record is exposed as a fixed-version candidate. VEX analysis is preserved in properties; VulnFuse does not convert VEX state into a false-positive verdict.

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

CSV references can be separated by whitespace, commas, or semicolons. Only HTTP(S) references survive normalization. CSV export prefixes spreadsheet-formula cells defensively.

## VulnFuse JSON

Canonical VulnFuse JSON can be supplied again as input. Valid cluster members are flattened into source findings and correlated under the new policy. Invalid members produce warnings rather than being silently accepted.

## Output contracts

A plain correlation exports the complete `CorrelationResult`. A baseline comparison exports a `BaselineDiffResult` containing baseline/current summaries and one item per `new`, `updated`, `unchanged`, or `absent` cluster. JSON preserves full evidence; CSV adds `baseline_state` and changed fields; Markdown focuses on changes; SARIF writes `baselineState` on every result and a stable `primaryLocationLineHash` partial fingerprint.

Every report summary has a primary `tool` plus a sorted `tools` list. The list records every producer represented by a mixed CSV file or multi-run SARIF document, including declared SARIF runs with zero findings.

Every correlation summary includes a deterministic `coverage` object. Its per-tool rows count input reports, source findings attributed to that tool, resulting clusters, clusters reported only by that tool, and clusters shared with another tool. Pair rows record the shared cluster count, the union count, and Jaccard overlap (`shared / union`). Pairwise rows are omitted when more than 20 distinct tools are present to bound quadratic output; complete per-tool counts remain available. These values describe attribution and overlap, not scanner accuracy, false-positive rate, or majority truth.

Scanner versions come from producer-specific fields such as SARIF `tool.driver.semanticVersion`, Trivy `Trivy.Version`, and CycloneDX `metadata.tools`. Report schema versions such as Trivy `SchemaVersion` and CycloneDX `specVersion` remain metadata and are not presented as scanner versions.

HTML is a self-contained review surface rather than a machine-ingestion format. It embeds no report JSON and loads no remote assets. All report-controlled text and attributes are escaped before rendering; its fixed inline script only filters and expands already-rendered findings. The file supports search and severity, baseline-state, asset, scanner, and one-tool/multi-tool filters while retaining match evidence, blockers, source records, and safe HTTP(S) references.

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

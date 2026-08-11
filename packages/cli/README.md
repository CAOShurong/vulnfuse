# vulnfuse CLI

Node.js command-line interface for [VulnFuse](https://github.com/CAOShurong/vulnfuse). It reads local scanner reports or standard input, applies the shared deterministic correlation engine, quantifies per-tool coverage and overlap, compares optional baseline reports, and writes JSON, SARIF, CSV, Markdown, or a self-contained interactive HTML report. Use `merge` for a single run and `diff` with repeatable `--baseline` inputs to gate only new findings.

`--max-bytes` rejects a file whose known size is already over the per-report limit before content reads, then enforces the same limit incrementally. Report-input failures are concise by default; put the global `--debug` option before the command to include a stack that may contain local paths.

Report arguments can be exact paths or quoted glob patterns. Use forward slashes for cross-platform patterns, for example `vulnfuse inspect "reports/**/*.json"`. Exact existing paths win over glob syntax; matches are file-only, do not follow symbolic-link directories, are deduplicated, and count toward the 1,000-report limit after expansion.

Baseline diffs record and warn about added/removed scanner tools and per-tool report-count changes. Add `--fail-on-scan-set-change` to make that warning fail CI after the complete comparison has been written. Equal names and counts do not prove that scan targets, settings, versions, rules, or vulnerability databases were identical.

SARIF suppression kinds, statuses, and justifications are retained. `--fail-on` and `--fail-on-new` ignore only clusters whose every source record is effectively suppressed; malformed, under-review, rejected, or actively corroborated records remain gate-eligible. This trusts producer metadata and is not an independent false-positive verdict.

The public package is not yet published to npm. Build and run it from the repository as documented in the root [README](../../README.md).

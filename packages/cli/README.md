# vulnfuse CLI

Node.js command-line interface for [VulnFuse](https://github.com/CAOShurong/vulnfuse). It reads local scanner reports or standard input, applies the shared deterministic correlation engine, quantifies per-tool coverage and overlap, compares optional baseline reports, and writes JSON, SARIF, CSV, Markdown, or a self-contained interactive HTML report. Use `merge` for a single run and `diff` with repeatable `--baseline` inputs to gate only new findings.

`--max-bytes` rejects a file whose known size is already over the per-report limit before content reads, then enforces the same limit incrementally. Report-input failures are concise by default; put the global `--debug` option before the command to include a stack that may contain local paths.

The public package is not yet published to npm. Build and run it from the repository as documented in the root [README](../../README.md).

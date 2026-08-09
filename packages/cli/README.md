# vulnfuse CLI

Node.js command-line interface for [VulnFuse](https://github.com/CAOShurong/vulnfuse). It reads local scanner reports or standard input, applies the shared deterministic correlation engine, quantifies per-tool coverage and overlap, compares optional baseline reports, and writes JSON, SARIF, CSV, Markdown, or a self-contained interactive HTML report. Use `merge` for a single run and `diff` with repeatable `--baseline` inputs to gate only new findings.

The public package is not yet published to npm. Build and run it from the repository as documented in the root [README](../../README.md).

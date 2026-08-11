# @vulnfuse/core

Shared, runtime-neutral TypeScript engine for the [VulnFuse](https://github.com/CAOShurong/vulnfuse) vulnerability-report correlation project.

It provides defensive parsers, a canonical evidence model, deterministic explainable matching, clustering, scanner coverage/overlap analytics, cross-run baseline comparison, and JSON/SARIF/CSV/Markdown/self-contained HTML exporters. The public package is not yet published to npm; use the repository workspace or the paired GitHub release packages.

The default entry point is runtime-neutral. Node.js adapters can import `readFileLimited` and `writeFileAtomic` from `@vulnfuse/core/node`. The reader rejects a known oversized file before content reads and enforces the limit again while reading. The writer flushes a unique temporary sibling before renaming it over the destination, so caught write failures preserve an existing complete file. The byte limit does not bound parsing, correlation, export, or total-process memory; atomic replacement and crash durability still depend on the filesystem.

See the root [README](../../README.md), [matching policy](../../docs/MATCHING.md), and [format contract](../../docs/FORMATS.md).

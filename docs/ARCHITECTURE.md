# Architecture

VulnFuse is one TypeScript monorepo with a shared deterministic core and three delivery surfaces.

```text
scanner reports
      │
      ▼
format detection → defensive parser adapters
      │
      ▼
canonical findings → candidate index → pair explanations
      │                                  │
      └──────────────────────────────────┘
                         │
                         ▼
               union-find clusters
                         │
             ┌───────────┼───────────┐
             ▼           ▼           ▼
          JSON/SARIF     CSV      Markdown

shared core ──► CLI
            ├─► GitHub Action
            └─► browser workbench
```

## Packages

### `@vulnfuse/core`

The core has no Node-only dependency. It contains:

- safe unknown-to-JSON helpers;
- format detection and parser adapters;
- identifier, path, severity, asset, and PURL normalization;
- canonical schemas and TypeScript types;
- match scoring and blockers;
- candidate indexing and union-find clustering;
- JSON, SARIF, CSV, and Markdown exporters.

The browser and Node runtimes execute the same correlation code.

### `vulnfuse` CLI

The CLI adds filesystem and standard-input handling, bounded reads, atomic output, overwrite protection, policy flags, inspection output, and severity exit codes. It does not contain a second implementation of parsing or matching.

### `@vulnfuse/action`

The repository-root `action.yml` invokes a Node 24 CommonJS bundle. The Action resolves bounded glob input without following symbolic links, invokes the core, writes the chosen report, exposes counts, and creates a GitHub job summary. The bundled `dist/index.cjs` is committed because JavaScript Actions execute repository content directly.

### `@vulnfuse/web`

The React/Vite application reads `File` objects into memory, calls the core, and renders clusters and evidence. Exports use browser `Blob` URLs. It has no backend and does not persist report content to local storage.

## Trust boundaries

The outer adapters treat every report as untrusted input. They validate structural assumptions with runtime type guards, cap file sizes, discard unsafe URL schemes, and never evaluate content. React escapes rendered strings. See [THREAT_MODEL.md](THREAT_MODEL.md).

## Determinism

Finding IDs use a stable FNV-1a hash over normalized source identity and evidence. Cluster IDs hash sorted member IDs and identifiers. Output ordering uses severity, member count, and stable IDs. Neither current time nor random values enter the canonical result.

## Performance

Parsing is linear in input size. Candidate indexing avoids complete all-pairs comparison at practical thresholds. Within each candidate bucket, pair comparison is quadratic in the bucket size; this is necessary when many records genuinely share an identity key. A hard comparison limit fails visibly instead of returning a partial result.

The browser keeps inputs and results in memory. For very large reports, use the CLI and split work by asset.

## Adding a parser

1. Add a format adapter under `packages/core/src/formats`.
2. Use `unknown` input plus the shared `asRecord`, `asArray`, and scalar guards.
3. Construct findings through `makeFinding`; never create unstable IDs manually.
4. Add a sanitized synthetic fixture and parser expectations.
5. Add detection rules that cannot shadow an existing format.
6. Document mapped fields and unsupported variants in `FORMATS.md`.

Parser adapters should preserve useful source properties without copying unnecessary large blobs into every canonical finding.

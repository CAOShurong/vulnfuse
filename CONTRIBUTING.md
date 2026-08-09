# Contributing to VulnFuse

VulnFuse benefits most from concrete, sanitized compatibility cases and narrowly explained changes. You do not need security-product expertise to contribute.

## Before opening an issue

- Confirm the report is one of the documented JSON/SARIF/CSV families.
- Run `vulnfuse inspect` or load the safe demo to separate an input problem from a browser problem.
- Search existing issues by scanner, format, and version.
- Remove organization names, internal paths, image registries, source fragments, tokens, and real secret matches.

Never attach a proprietary report merely because a repository is public.

## Development setup

Requirements: Node.js 22.12 or newer and npm.

```bash
git clone https://github.com/CAOShurong/vulnfuse.git
cd vulnfuse
npm ci
npm run verify
```

Useful commands:

```bash
npm run dev          # local browser workbench
npm test             # all workspace tests
npm run typecheck    # strict TypeScript checks
npm run lint         # ESLint
npm run format       # apply Prettier
npm run build        # core, CLI, web, and bundled Action
npm run demo:cli     # deterministic Trivy + Grype demonstration
```

## Pull requests

1. Keep the change focused and explain the user-visible failure or benefit.
2. Add or update tests for behavior changes.
3. Update `FORMATS.md` for mapping changes and `MATCHING.md` for policy changes.
4. Run `npm run verify` from a clean install.
5. Do not manually edit `packages/action/dist/index.cjs`; run the Action build.
6. Call out compatibility, security, performance, and output-schema effects.

The Action bundle is expected in review because tagged Actions cannot install dependencies before entrypoint execution.

## Fixture policy

Test fixtures must be synthetic or demonstrably public and redistributable. Prefer the smallest structure that reproduces the behavior.

A good format fixture includes:

- scanner and version family;
- representative IDs, PURLs, assets, locations, severity, and remediation;
- an expected canonical finding count;
- at least one assertion for the field under test;
- deterministic placeholder names such as `acme/payments` or `registry.example.com`.

Do not add large raw reports, binary databases, malware, credentials, secret values, customer data, or scraped vulnerability feeds.

## Matching-policy changes

Correlation changes have a higher review bar because they can merge unrelated work or split one remediation into several clusters. Include:

- a pair that should match;
- a nearby pair that must not match;
- the expected score, reasons, and blockers;
- instance- and root-cause expectations when assets differ;
- a short migration note if stable cluster IDs could change.

## Commit and review scope

Readable conventional-style subjects are welcome but not required. Maintainers may ask to split parser, UI, and policy work when their risks differ.

By contributing, you agree that your contribution is licensed under Apache-2.0 and that you have the right to submit any included fixture.

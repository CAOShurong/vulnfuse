# Synthetic demo reports

Three small **synthetic** scanner reports for trying VulnFuse without your own
scanner output. Every finding references the fictional
`registry.example.com/acme/payments:1.0.0` image; no real inventory, host, or
secret is described. The CVE identifiers are real published vulnerabilities,
which keeps correlation realistic, but the artifact and environment around them
are invented.

| File              | Format     |                                      Findings |
| ----------------- | ---------- | --------------------------------------------: |
| `demo-trivy.json` | Trivy JSON |          2 (Log4Shell CRITICAL, openssl HIGH) |
| `demo-grype.json` | Grype JSON | 2 (Log4Shell + alias, zlib MiniZip not-fixed) |
| `demo-snyk.json`  | Snyk JSON  |                     1 (Log4Shell via SNYK ID) |

All three describe the same fictional image, so correlating them produces one
multi-scanner Log4Shell cluster plus single-tool findings — enough to see
matching evidence, scanner overlap, and disagreement in one report.

These are the same fixtures the hosted workbench loads for its
**Load safe demo** button (`apps/web/src/demo.ts`), kept here as plain files so
the CLI can use them too.

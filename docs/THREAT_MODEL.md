# Threat model

VulnFuse processes potentially sensitive and attacker-controlled scanner reports. This document describes the v0.2.x trust boundary and remaining risks.

## Assets to protect

- repository paths, package inventories, image names, hostnames, and application names;
- source locations and snippets included by scanners;
- secret matches accidentally embedded in a report;
- CI credentials and filesystem integrity;
- reviewer trust in correlation results.
- historical baseline reports and the conclusions drawn from missing findings.

## Deployment modes

### Hosted browser workbench

The static GitHub Pages application has no report-processing backend. File content is read with the browser `File` API, kept in React memory, passed to the shared core, and exported through a temporary `Blob` URL. Report content is not written to local storage or sent by application code.

The page still originates from GitHub Pages, so normal hosting infrastructure can observe ordinary page requests. Do not confuse “no report upload” with anonymous browsing.

### CLI

The CLI reads only named input paths or standard input and writes only the requested output path. It rejects an output path that resolves to an input file and writes through a temporary sibling before rename.

### GitHub Action

The Action runs inside the calling repository's runner. Glob expansion does not follow symbolic links and does not match directories. The Action needs no network permission or credential. Other workflow steps and scanner actions remain outside VulnFuse's boundary.

## Implemented safeguards

| Risk                                   | Mitigation                                                                                        |
| -------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Oversized report memory exhaustion     | 100 MiB per-report default in browser, CLI, and Action                                            |
| Excessive file expansion               | 1,000-report limit in CLI/Action/browser                                                          |
| Quadratic matching denial of service   | Candidate indexing; 2,000,000 finding/source-record pair limits; 1,000,000 baseline-cluster limit |
| Output destroys an input               | CLI and Action reject identical resolved input/output paths                                       |
| Symlink escape in Action globbing      | Symbolic-link following is disabled                                                               |
| Script or HTML injection in workbench  | React text rendering; no `dangerouslySetInnerHTML`                                                |
| Unsafe advisory schemes                | Only HTTP(S) references survive parser normalization                                              |
| Spreadsheet formula injection          | CSV exporter enables formula escaping                                                             |
| Remote code execution from report data | No template evaluation, dynamic import, shell construction, or executable deserialization         |
| Silent evidence loss                   | Source members and actual match edges remain attached to clusters                                 |
| Unsafe false merge                     | Explicit identity, component, asset, and kind conflicts can block merging                         |

## Important residual risks

1. **Browser extensions and compromised hosting can observe page data.** A malicious extension with page access or a compromised browser profile is outside the application's control. Use the CLI in an isolated environment for highly sensitive reports.
2. **Memory use remains proportional to report and finding count.** The browser reads each accepted file fully into memory. The size limit is per file, not a guarantee that a device can handle the aggregate.
3. **Correlation can still be wrong.** Vendor reports can contain incomplete or incorrect identifiers. Transitive clustering can connect A to C through B. Review match edges before using a cluster for remediation or compliance.
4. **Exports can propagate sensitive content.** Downloaded JSON, SARIF, CSV, and Markdown retain evidence. Protect them as you would the original reports.
5. **References are not validated for safety or truth.** HTTP(S) allowlisting prevents active schemes, but a reference can still point to a malicious or misleading site. Opening it is an explicit user action.
6. **The Action bundle includes dependencies.** Review `packages/action/dist/index.cjs`, pin a release or commit SHA, and use normal GitHub Actions supply-chain controls.
7. **An absent finding is not proof of a fix.** A baseline cluster can disappear because a scanner failed, changed configuration, or did not scan the same asset. Treat `absent` as missing current evidence until another control verifies remediation.
8. **Baseline mode retains two report sets.** Browser and runner memory use can approach the combined size of the baseline and current inputs, plus their parsed models and comparison output.

## Non-goals

VulnFuse does not:

- determine whether a vulnerability is exploitable or reachable;
- verify that a fixed version was deployed;
- replace VEX, risk acceptance, or vulnerability-management approval;
- fetch missing aliases or live advisory data;
- remove secrets from an input report;
- provide a multi-user authorization boundary.

## Reporting a vulnerability

Do not publish a live exploit, token, or proprietary report in an issue. Follow [SECURITY.md](../SECURITY.md) to report privately and include the smallest synthetic reproducer possible.

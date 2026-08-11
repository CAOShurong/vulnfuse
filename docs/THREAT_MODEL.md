# Threat model

VulnFuse processes potentially sensitive and attacker-controlled scanner reports. This document describes the v0.4.x trust boundary and remaining risks.

## Assets to protect

- repository paths, package inventories, image names, hostnames, and application names;
- source locations and snippets included by scanners;
- secret matches accidentally embedded in a report;
- CI credentials and filesystem integrity;
- reviewer trust in correlation results.
- historical baseline reports and the conclusions drawn from missing findings.

## Deployment modes

### Hosted browser workbench

The static GitHub Pages application has no report-processing backend. File content is read with the browser `File` API, kept in React memory, passed to the shared core, and exported through a temporary `Blob` URL. Report content is not written to local storage or sent by application code. Its strict CSP does not allow dynamic code generation; Zod's optional JIT is disabled so validation does not probe blocked `eval` behavior.

The page still originates from GitHub Pages, so normal hosting infrastructure can observe ordinary page requests. Do not confuse “no report upload” with anonymous browsing.

### CLI

The CLI reads only named input paths, files matched by named glob patterns, or standard input and writes only the requested output path. It rejects an output path that resolves to an expanded input file and writes through a temporary sibling before rename. Glob expansion matches files only and does not follow symbolic-link directories.

### GitHub Action

The Action runs inside the calling repository's runner. Glob expansion does not follow symbolic links and does not match directories. Reports are written through a temporary sibling before replacement, matching the CLI. The Action needs no network permission or credential. Other workflow steps and scanner actions remain outside VulnFuse's boundary.

## Implemented safeguards

| Risk                                     | Mitigation                                                                                        |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Oversized report memory exhaustion       | 100 MiB per-report default; browser size check; CLI/Action metadata preflight and bounded read    |
| Excessive file expansion                 | 1,000-report limit after CLI/Action expansion and before report reads                             |
| Quadratic matching denial of service     | Candidate indexing; 2,000,000 finding/source-record pair limits; 1,000,000 baseline-cluster limit |
| Quadratic scanner-pair output            | Complete pairwise coverage rows only when 20 or fewer tools are present                           |
| Output destroys an input                 | CLI and Action reject identical resolved input/output paths                                       |
| Baseline coverage drift is misread       | Structured scanner/report-count drift warning; optional post-write CLI/Action failure             |
| Failed SARIF run looks complete          | Preserve partial findings; targeted run-health warnings; optional post-write CLI/Action failure   |
| Malformed suppression bypasses a gate    | Unknown containers, kinds, or statuses warn and remain active; mixed clusters remain active       |
| Malformed result kind bypasses a gate    | Unknown, non-string, or contradictory kinds warn and remain active; active corroboration wins     |
| Untrusted OpenVEX bypasses a gate        | VEX status is preserved but never converted into suppression or non-finding state                 |
| Failed output write exposes partial data | Unique exclusive temporary sibling, flush, rename, and cleanup on reported failure                |
| Symlink escape in Action globbing        | Symbolic-link following is disabled                                                               |
| Script or HTML injection in workbench    | React text rendering; no `dangerouslySetInnerHTML`                                                |
| Script or HTML injection in HTML export  | Contextual escaping; fixed data-free script/style blocks; restrictive Content Security Policy     |
| Unsafe advisory schemes                  | Only HTTP(S) references are rendered as links in portable HTML                                    |
| Spreadsheet formula injection            | CSV exporter enables formula escaping                                                             |
| Remote code execution from report data   | No template evaluation, dynamic import, shell construction, or executable deserialization         |
| Silent evidence loss                     | Source members and actual match edges remain attached to clusters                                 |
| Unsafe false merge                       | Explicit identity, component, asset, and kind conflicts can block merging                         |

## Important residual risks

1. **Browser extensions and compromised hosting can observe page data.** A malicious extension with page access or a compromised browser profile is outside the application's control. Use the CLI in an isolated environment for highly sensitive reports.
2. **Memory use remains proportional to accepted report and finding count.** The browser reads each accepted file fully into memory. The CLI and Action avoid reading a file whose known size is already over the limit and stop a growing or unusual file after one byte beyond it, but accepted text, parsed models, correlation state, and exports still coexist. The size limit is per file, not a guarantee that a device can handle the aggregate.
3. **Correlation can still be wrong.** Vendor reports can contain incomplete or incorrect identifiers. Transitive clustering can connect A to C through B. Review match edges before using a cluster for remediation or compliance.
4. **Exports can propagate sensitive content.** Downloaded JSON, SARIF, CSV, Markdown, and HTML retain evidence. Protect them as you would the original reports. The portable HTML makes no network request by itself, but opening an advisory link is an explicit navigation and browser extensions can still observe the page.
5. **References are not validated for safety or truth.** HTTP(S) allowlisting prevents active schemes, but a reference can still point to a malicious or misleading site. Opening it is an explicit user action.
6. **The Action bundle includes dependencies.** Review `packages/action/dist/index.cjs`, pin a release or commit SHA, and use normal GitHub Actions supply-chain controls.
7. **An absent finding is not proof of a fix.** A baseline cluster can disappear because a scanner failed, changed configuration, or did not scan the same asset. Treat `absent` as missing current evidence until another control verifies remediation.
8. **Baseline mode retains two report sets.** Browser and runner memory use can approach the combined size of the baseline and current inputs, plus their parsed models and comparison output.
9. **Coverage statistics can be misread.** A tool may appear exclusive because it scanned a different asset, package inventory, configuration, database snapshot, or advisory namespace. Pairwise overlap is not an accuracy score.
10. **Atomic replacement is filesystem-dependent.** A caught write or rename error preserves the old destination and cleans its temporary sibling, but a hard termination can leave a `.vulnfuse-*.tmp` file. The implementation does not claim directory-fsync power-loss durability or atomic replacement on every network or unusual filesystem.
11. **Glob traversal happens before the report-count limit.** A quoted CLI pattern does not follow symbolic-link directories and cannot make VulnFuse process more than 1,000 reports, but a broad pattern can still traverse a large directory tree and allocate its match list before that count is checked. Treat workflow-provided patterns as filesystem-read authority and scope them to a known report directory.
12. **A stable scan set is not proven comparable.** VulnFuse warns when tool names or per-tool report counts change. Equal names and counts still cannot establish identical assets, scanner configuration/version, rules, advisory database, or successful scan completion; retain scanner logs and provenance for consequential baseline decisions.
13. **Suppression is an assertion, not independent validation.** A scanner or postprocessor can mark a SARIF result suppressed and provide a misleading justification. VulnFuse preserves that evidence and applies current SARIF disposition semantics, but it does not authenticate the producer, prove risk acceptance, or synchronize dismissal state with GitHub or another vulnerability-management system. Protect gate inputs and review consequential suppressions.
14. **A non-finding result kind is also an assertion.** A compromised, buggy, or misconfigured producer can label a result `pass`, `informational`, or `notApplicable`. VulnFuse rejects malformed or contradictory combinations and lets active corroborating evidence win, but it does not rerun the rule, verify the target, or prove applicability. Protect gate inputs and retain scanner execution logs for consequential decisions.
15. **OpenVEX status and authorship are not authenticated.** A standalone document can claim `not_affected` or `fixed` without a valid signature, complete product scope, or sound analysis. VulnFuse keeps those labels active and visible, does not fetch JSON-LD contexts or unwrap attestations, and does not verify signatures, authors, reachability, or remediation. Validate provenance through the distribution channel before relying on a VEX assertion outside VulnFuse.
16. **Run-health metadata is useful but producer-controlled and optional.** VulnFuse warns on SARIF's documented incomplete-result signals and can fail after preserving the output. A compromised or buggy producer can falsely claim success, omit invocations, or fail to describe unscanned targets and rules. The absence of an incomplete warning is not proof of coverage; retain the scanner exit status, logs, configuration, and target inventory for consequential decisions.

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

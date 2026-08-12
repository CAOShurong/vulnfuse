# Why VulnFuse exists

VulnFuse was selected after comparing several open-source project directions in August 2026, including local file transfer, export viewers, metadata sanitizers, Windows cleanup, location-history tools, vector conversion, browser-extension auditing, DAV clients, and security-report normalization.

The selected problem had the strongest combination of repeated user pain, open standards, multiple mature input producers, and room for a standalone local-first tool rather than another hosted dashboard.

## The practical gap

Teams increasingly run more than one scanner, but the resulting rows are neither independent evidence nor safely interchangeable. Cross-tool matching requires care because tools use different identifiers, package metadata, locations, severities, and assumptions.

This is visible even in mature vulnerability-management products. DefectDojo documents that cross-tool deduplication is disabled by default because tools report the same vulnerabilities differently, warns that broad settings can create false duplicates, and requires aligned configuration across participating tools. Its global component algorithm is a Pro feature and matches exact component names and versions across products. See DefectDojo's [deduplication tuning](https://docs.defectdojo.com/triage_findings/finding_deduplication/pro__deduplication_tuning/) and [global component deduplication](https://docs.defectdojo.com/triage_findings/finding_deduplication/pro__global_component_deduplication/) documentation.

A large August 2026 preprint covering 52,895 high-exposure Docker Hub repositories reported substantial scanner divergence: 66.8% of distinct vulnerability/package groups were flagged by only one of three vulnerability scanners and 2.7% by all three. This is not proof that any one scanner was correct, and the paper is recent rather than settled consensus; it does show why provenance must survive normalization. See [Vulnerabilities, Secrets and Misconfiguration in the Highest-Exposure Docker Hub Images](https://arxiv.org/abs/2608.02669).

VulnFuse therefore does not turn disagreement into a single verdict. It retains source records and makes the correlation claim inspectable.

## Why OpenVEX must be ingestible without becoming a trusted verdict

OpenVEX is an active interchange path rather than a speculative format. The
OpenVEX specification defines a statement as a vulnerability, one or more
products, a status, and a timestamp; subcomponents identify dependencies where
the vulnerability originates. Trivy 0.73.0 accepts OpenVEX for container,
filesystem, repository, VM, Kubernetes, and SBOM targets and documents PURL
matching and subcomponent scoping. Grype 0.117.0 likewise advertises OpenVEX
filtering and result augmentation. See the OpenVEX [statement and product
model](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md), Trivy's
[local VEX documentation](https://trivy.dev/docs/latest/guide/supply-chain/vex/file/),
and Grype's [maintained repository](https://github.com/anchore/grype).

The public v0.4.11 CLI could not detect either of two pinned inputs. The
OpenVEX project's `vexctl` v0.4.4 repository supplies one OpenVEX document next
to Trivy, Grype, and Snyk SARIF fixtures for the same nginx workflow; the
630-byte OpenVEX file at commit
`d344883b69c29d7b8ec11b146743db77630fc6b8` had SHA-256
`873E10D746EA29B7C7C4DB9AF42E5B95C3A01CD7D80DC73D1FB28A8E3A901F2D`.
Aqua's public VEX Hub provided a non-demo production document at commit
`8ae2a8c69e5958df726d228327a2c5fb13c2e640`; its 20,039-byte Trivy document
had SHA-256
`355CB4744029DF01F1E6AAD8F7446DEDA26F0FA6AD03E5D301EE740229146EA5`
and contained 21 statements, 21 products, and 21 subcomponents. Both inputs
returned `Could not detect the report format` before this change. See the
[`vexctl` cross-tool fixtures](https://github.com/openvex/vexctl/tree/d344883b69c29d7b8ec11b146743db77630fc6b8/examples/sarif)
and the pinned [Aqua VEX Hub
document](https://github.com/aquasecurity/vexhub/blob/8ae2a8c69e5958df726d228327a2c5fb13c2e640/pkg/golang/github.com/aquasecurity/trivy/trivy.openvex.json).

Interoperability remains uneven outside those scanners. A Dependency-Track
user described a repository-and-CI VEX workflow in which `vexctl` produced
OpenVEX, Dependency-Track rejected the document, and an attempted conversion
to CycloneDX VEX still failed. This is one practitioner report rather than a
usage survey, but it demonstrates the concrete conversion and migration cost
of a format boundary. See the [Dependency-Track and VEX
thread](https://www.reddit.com/r/devsecops/comments/1rx059b/dependency_track_and_vex/)
and Dependency-Track [issue #4862](https://github.com/DependencyTrack/dependency-track/issues/4862).

Maintained alternatives solve adjacent layers:

- [`vexctl` 0.4.4](https://github.com/openvex/vexctl/releases/tag/v0.4.4)
  is Apache-2.0 and creates, transforms, filters, and attests OpenVEX, but it is
  a Go CLI rather than a TypeScript cross-scanner correlation library. Its open
  issues include a [reported vulnerable cosign dependency](https://github.com/openvex/vexctl/issues/413)
  and [broken attestation signing](https://github.com/openvex/vexctl/issues/428),
  so importing that stack would widen VulnFuse's runtime and security boundary
  rather than merely parse evidence.
- [Trivy 0.73.0](https://github.com/aquasecurity/trivy/releases/tag/v0.73.0)
  and [Grype 0.117.0](https://github.com/anchore/grype/releases/tag/v0.117.0)
  are maintained Apache-2.0 standalone scanners. Their native VEX application
  is the right choice inside each scan, but neither replaces review of several
  already-generated heterogeneous reports.
- [Dependency-Track 5.0.4](https://github.com/DependencyTrack/dependency-track/releases/tag/5.0.4)
  is a maintained Apache-2.0 server and database platform. It provides a broader
  inventory and policy lifecycle with correspondingly greater operating and
  migration cost, and the cited workflow still required CycloneDX conversion.
- [`openvex-js` 0.0.1](https://www.npmjs.com/package/openvex-js) is MIT,
  about 159 KB unpacked, and requires Zod plus the Temporal polyfill as peer
  dependencies. It is a new single-release model implementation; adopting it
  would not supply VulnFuse's canonical mapping or correlation behavior.

The selected parser therefore reuses VulnFuse's existing defensive JSON and
`packageurl-js` helpers and adds no dependency or service. Every product and
listed subcomponent becomes attributable evidence. Valid PURLs can correlate
with scanner evidence; arbitrary IRIs and hashes remain preserved without
being guessed into package identities.

The trust boundary is stricter than scanner-native VEX filtering. OpenVEX
`not_affected`, `affected`, `fixed`, and `under_investigation` labels are kept
as producer assertions but never converted into VulnFuse suppression or
non-finding state. The parser does not fetch JSON-LD contexts, discover remote
documents, unwrap or verify attestations, authenticate authors, apply version
ranges, or prove reachability or exploitability. This makes OpenVEX reviewable
beside scanner output without turning an unverified file into a gate bypass.

## Trivy SARIF container identity compatibility (v0.4.24)

The public v0.4.23 CLI packages and Action bundle detected three Apache-2.0
upstream reports but lost a relationship already present in their producer
metadata. The pinned `openvex/vexctl` v0.4.4 examples at commit
`d344883b69c29d7b8ec11b146743db77630fc6b8` contain a Trivy 0.42.1 SARIF report
and a two-statement OpenVEX document for the same nginx workflow. Their
SHA-256 values were
`F7E17D76E74E79C509BBBA2FE7763309ADD64B7FC1900DD6115788E6E77FD89D`
and `8871FB050E23EF16F24969067CB77D60DBEFCDD50870F0390C83B0C8AA6C4128`.
A third native Trivy JSON fixture came from Trivy v0.73.0 commit
`40c73e5d6166dcc0346a1ab4e94499d1572854e4` and had SHA-256
`DF6055C1B1CD54229A3095EAD3A41455F0C48C7538F8FA8D6413ABB2ADAF7D06`.
See the pinned [`vexctl` examples](https://github.com/openvex/vexctl/tree/d344883b69c29d7b8ec11b146743db77630fc6b8/examples/sarif),
the [Trivy fixture](https://github.com/aquasecurity/trivy/blob/40c73e5d6166dcc0346a1ab4e94499d1572854e4/integration/testdata/gomod-vex.json.golden),
and Trivy's [SARIF writer](https://github.com/aquasecurity/trivy/blob/40c73e5d6166dcc0346a1ab4e94499d1572854e4/pkg/report/sarif.go#L137-L143).

The Trivy SARIF run supplies `imageName` and `repoDigests` for
`nginx@sha256:13d22e...`, while the OpenVEX products use the equivalent OCI
PURL. VulnFuse v0.4.23 ignored the run properties, modeled 99 container results
as SAST on `file:library/nginx`, and kept both matching OpenVEX statements in
separate single-tool clusters even under root-cause scope. Across both the
installed CLI and extracted Action, 105 source records became 66 clusters with
zero multi-tool clusters. Two different checkout roots produced byte-identical
outputs, proving that the already-fixed source-report label was not the cause.

Trivy v0.73.0 still emits the same four run properties for container images.
The selected repair therefore extends the existing defensive SARIF mapping
rather than adding a converter, scanner, service, or dependency. Only a
Trivy-named run with one unambiguous SHA-256 container identity gets an OCI PURL
and image asset; different, malformed, or ambiguous metadata stays unguessed.
The fixed real merge retains all 105 source records in 64 clusters, including
two multi-tool clusters for the matching CVEs. Both OpenVEX records remain
active and gate-eligible. This is interoperability evidence from upstream test
fixtures, not independent adoption or proof that either producer's security
conclusion is correct.

## Why an external VEX reference can carry package identity

CycloneDX explicitly recommends separating dynamic VEX statements from a
comparatively static SBOM and linking an affected target back to the precise
inventory component with `vulnerabilities[].affects[].ref`. Its official guide
shows an external BOM-Link element in that field. The maintained CycloneDX
`sbom-utility` goes one step further in a public VEX example: the BOM-Link
fragment is the component's complete `pkg:maven/...` Package URL. These are
primary examples of a real interchange path, not a VulnFuse-specific
convention. See the CycloneDX [external VEX guidance](https://cyclonedx.org/guides/sbom/relationships/#linking-external-vex-to-bom-inventory),
the [BOM-Link schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json),
and the official [`sbom-utility` VEX example](https://github.com/CycloneDX/sbom-utility/blob/776791771674f4f6ee1af29dd468c59c5ae995e0/examples/cyclonedx/VEX/vex.json).

The public v0.4.10 parser kept the complete external URN in source properties
but looked only for an in-document component with the same `bom-ref`. In a VEX
that intentionally contains no inventory, the resulting finding had no
component PURL. A second report with the same CVE and the PURL therefore lacked
enough shared evidence to meet the default correlation threshold and remained
a separate singleton. The parser also read only `affects[0]`, so later affected
targets disappeared from the canonical finding set entirely.

The full `@cyclonedx/cyclonedx-library` 10.1.1 model was checked on 2026-08-11.
It is maintained, Apache-2.0, dependency-free, and about 5.2 MB unpacked; it is
a strong choice for applications that need complete schema construction and
validation. VulnFuse already depends on MIT-licensed `packageurl-js` 2.0.1
(about 57 KB unpacked) for its cross-format identity layer. Adding the full
model only to recognize a validated PURL fragment would materially widen the
core, browser, and committed Action bundle without resolving external
documents. The selected change therefore uses the existing PURL parser, adds
no runtime dependency or network request, and expands all affected targets.

This is intentionally conservative. The complete BOM-Link element syntax must
match before its fragment is considered, and that fragment must parse as a
PURL. Product ids such as `#product-JKL`, hashes, and other legitimate
`bom-ref` forms are not package identities and remain unresolved unless the
referenced inventory is available. VulnFuse does not fetch that inventory,
authenticate the VEX producer, or turn `analysis.state` into a suppression or
exploitability verdict.

## Why pairwise matches are not enough

The v0.4.2 correlator had a reproducible cluster-level failure even though its pairwise blocker rules worked as documented. Scanner A and Scanner B could match through one CVE, while Scanner B and Scanner C matched through another ID. Union-find transitive closure then put all three records in one cluster even when A and C named conflicting components and `explainMatch(A, C)` returned hard blockers. The resulting scanner-overlap table also described A and C as shared because it only saw the final cluster.

This is a known risk beyond vulnerability tooling. Splink's maintained record-linkage documentation separates pair/edge evaluation from cluster evaluation and recommends inspecting clusters for inaccurate links; its default threshold clustering uses connected components. Research on entity matching reports that enforcing transitivity with an ad-hoc closure can sharply reduce precision. See Splink's [cluster evaluation guide](https://moj-analytical-services.github.io/splink/topic_guides/evaluation/clusters/overview.html), [connected-components API](https://moj-analytical-services.github.io/splink/api_docs/linker_clustering.html), and the paper [Exploiting Transitivity Constraints for Entity Matching in Knowledge Graphs](https://arxiv.org/abs/2104.12589).

The same cost is visible in vulnerability-management practice. DefectDojo disables cross-tool deduplication by default, warns that broad field choices create false duplicates, and places fine-grained cross-tool tuning in its Pro product. A long-running public issue also documents inconsistent deduplication behavior between import paths. See [Deduplication Tuning](https://docs.defectdojo.com/triage_findings/finding_deduplication/pro__deduplication_tuning/) and [DefectDojo issue #1145](https://github.com/DefectDojo/django-DefectDojo/issues/1145).

VulnFuse therefore keeps its lightweight local architecture but no longer treats every connected component as safe. Candidate edges are ordered by evidence strength, and every proposed cluster union is rejected when any cross-cluster member pair has a hard blocker. This is a conservative constraint, not a claim that the remaining clusters are ground truth.

### Maintained alternatives revisited on 2026-08-11

| Alternative                                                                                                                                            | Current fit and maintenance signal                                                                                                    | License and dependency/operating cost                                                                                    | Migration trade-off                                                                                                                                  |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| [DefectDojo 3.2.100](https://github.com/DefectDojo/django-DefectDojo/releases/tag/3.2.100)                                                             | Full vulnerability-management platform with active import, triage, deduplication, and workflow development                            | BSD-3-Clause; deployed application, workers, database, and operational administration; advanced cross-tool tuning is Pro | Strong choice when a team wants a system of record, but much heavier than a local report preprocessor and not a drop-in library                      |
| [Dependency-Track 5.0.4](https://github.com/DependencyTrack/dependency-track/releases/tag/5.0.4)                                                       | Actively maintained SBOM analysis and VEX platform; practitioner reports still show ordering and ingestion friction when applying VEX | Apache-2.0; Java service plus persistent database and SBOM lifecycle                                                     | Appropriate for portfolio inventory and policy, but adopting it changes storage and workflow ownership rather than just correlating existing reports |
| [Splink 4.0.16](https://github.com/moj-analytical-services/splink/releases/tag/v4.0.16)                                                                | Mature general-purpose probabilistic record linkage with explicit edge/cluster evaluation tools                                       | MIT; Python with a query-engine/data-science stack and a model-selection workflow                                        | Reusable for custom entity resolution, but users must design features, thresholds, QA, and vulnerability-format adapters themselves                  |
| [SARIF SDK 5.6.0](https://github.com/microsoft/sarif-sdk/releases/tag/v5.6.0)                                                                          | Maintained .NET SARIF manipulation and validation tooling                                                                             | MIT; .NET toolchain; operates on SARIF rather than Trivy, Grype, CycloneDX, OSV, Snyk, and CSV together                  | Good when every producer already emits SARIF; conversion and vulnerability-specific identity policy remain external                                  |
| [Trivy 0.73.0](https://github.com/aquasecurity/trivy/releases/tag/v0.73.0) and [Grype 0.117.0](https://github.com/anchore/grype/releases/tag/v0.117.0) | Maintained scanners and report producers, not cross-scanner correlation layers                                                        | Apache-2.0, standalone Go binaries; no additional service required for scanning                                          | Keep using them as evidence sources; replacing either does not solve review of their disagreement                                                    |

Dependency-Track's [VEX ingestion issue #4862](https://github.com/DependencyTrack/dependency-track/issues/4862) also shows why VEX is not a simple substitute for safe correlation: the discussion explicitly asks how deduplicated components should behave when analyses are ambiguous. VulnFuse preserves VEX context but still does not declare a finding exploitable, suppressed, or false positive.

The same boundary applies to scanner comparison. In a Trivy discussion, one project produced 10 findings in Trivy, 14 in Grype, and 45 in Dependency-Check; 31 of the extra findings were later traced to false package matches, and a Trivy maintainer warned that different matching policies make raw-count comparisons unreliable. See [Trivy discussion #7572](https://github.com/aquasecurity/trivy/discussions/7572). VulnFuse therefore reports per-tool exclusive/shared clusters and pairwise Jaccard overlap, while explicitly refusing to call a one-tool finding wrong or a multi-tool finding correct.

The queue also needs a time dimension. The OASIS SARIF 2.1 specification defines `new`, `unchanged`, `updated`, and `absent` baseline states so producers can distinguish newly introduced results from a standing backlog. GitHub code scanning similarly relies on stable partial fingerprints to track logical results across runs, and DefectDojo's reimport workflow distinguishes untouched, closed, and reactivated findings. See the SARIF [`baselineState` definition](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), GitHub's [data for preventing duplicated alerts](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support#data-for-preventing-duplicated-alerts), and DefectDojo's [reimport behavior](https://docs.defectdojo.com/import_data/import_intro/reimport/).

## Why portable HTML is a product surface

Readable offline reporting is a recurring scanner-adoption problem rather than a decorative export. Trivy users asked for interactive severity filtering, grouping, totals, and a way to turn existing JSON into HTML; the resulting discussion produced a separate interactive-report plugin rather than a built-in aggregation layer. Another Trivy user asked how to turn a Kubernetes JSON scan into a viewable report grouped by image or namespace and was directed toward third-party tooling. See [Trivy #2298](https://github.com/aquasecurity/trivy/issues/2298), [Trivy #2661](https://github.com/aquasecurity/trivy/issues/2661), and [Trivy discussion #3591](https://github.com/aquasecurity/trivy/discussions/3591).

The multi-report boundary is even clearer in Grype. A user requested one HTML report aggregated from JSON outputs produced by several container jobs; a maintainer described aggregation as outside Grype's scope and explicitly encouraged a separate tool that could consume multiple generated reports. See [Grype #2101](https://github.com/anchore/grype/issues/2101).

These threads are practical evidence, not a usage forecast. The design inference is that VulnFuse can fill a narrow gap scanners intentionally leave open: combine several already-generated reports, preserve provenance, and produce one searchable file without requiring a hosted dashboard, database, template installation, or live service.

## Why a shared identity layer is feasible

The ecosystem already provides useful identity primitives:

- The OASIS [SARIF 2.1 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) defines result fingerprints and partial fingerprints specifically to support stable logical identity, while warning that absolute line numbers are unstable fingerprint ingredients.
- The OpenSSF [OSV schema](https://ossf.github.io/osv-schema/) defines aliases as symmetric and transitive and distinguishes aliases from upstream and merely related vulnerabilities. This supports relationship-aware identifier handling instead of treating every referenced ID as equivalent.
- The [Package URL specification](https://github.com/package-url/purl-spec) provides a standardized `pkg:` identity with type, namespace, name, version, qualifiers, and subpath. VulnFuse parses PURLs instead of comparing their raw spelling.
- CycloneDX treats [VEX as a core capability](https://cyclonedx.org/guides/sbom/external-references) that describes exploitability in a product context. VulnFuse preserves that context but does not reinterpret it as a universal false-positive decision.

These standards do not provide a complete cross-scanner correlation policy. They provide the evidence from which a conservative, reviewable policy can be built.

## Why runtime errors are concise by default

A fresh installation of the public v0.4.3 release returned the correct exit code for a missing report and did not create the requested output, but Node.js printed 31 lines of runtime frames. The useful information was already present in the error message: the `ENOENT` code, failed `open` operation, and missing path. The remaining stack exposed internal module and local filesystem paths without helping the ordinary correction.

This behavior came from an uncaught rejection at the executable entry point, not from a parsing limitation. Node.js documents that uncaught exceptions print a stack and terminate the process; Commander documents asynchronous action handlers through `parseAsync`, so the rejection can be handled at that boundary without another dependency. Mature scanner CLIs such as Trivy expose a deliberate global `--debug` mode rather than making verbose diagnostics the default. See the Node.js [process error behavior](https://nodejs.org/api/process.html#event-uncaughtexception), Commander's [`parseAsync` guidance](https://github.com/tj/commander.js#action-handler), and Trivy's [global CLI options](https://trivy.dev/docs/latest/references/configuration/cli/trivy/).

VulnFuse therefore prints one `vulnfuse: <message>` line for runtime and report-input failures, preserves exit code 1 and clean stdout, and provides an explicit `--debug` escape hatch. Debug stacks may contain local paths and should be reviewed before sharing. This is a usability and log-hygiene improvement, not a security-boundary claim.

## Why a post-read byte check is not a memory bound

The public v0.4.4 CLI rejected an oversized report correctly, but its file path called `readFile` before comparing the returned buffer length with `--max-bytes`; the GitHub Action used the same order. In one local Windows probe, a synthetic 128 MiB file with a 1 MiB limit exited 1 with clean stdout and no output file, but reached a sampled 183.9 MiB peak working set because the full file was buffered first. The timing and memory number is one synthetic run, not a general benchmark; the source order independently establishes the allocation-before-check behavior.

Node.js documents `readFile` as reading the entire contents, and its `FileHandle` API exposes metadata, bounded `read` calls, and explicit close behavior. MITRE's CWE-400 guidance treats allocations triggered without an effective resource limit as an availability risk and recommends enforcing predetermined limits. See the Node.js [file-system API](https://nodejs.org/api/fs.html) and [CWE-400](https://cwe.mitre.org/data/definitions/400.html).

VulnFuse now opens each Node-side input once, rejects a known oversized file from metadata before content reads, and still stops after at most `maxBytes + 1` observed bytes if a file grows or metadata is not predictive. The handle closes on every path. This bounds input acquisition rather than total memory: accepted text is decoded and parsed into additional objects, multiple reports coexist during correlation, and a blocking device can still consume time. The browser keeps its separate `File`-size check and browser memory model.

## Why the Action must not expose a report while writing it

The v0.4.5 CLI already wrote a temporary sibling and renamed it over the requested destination, but the GitHub Action called `fsPromises.writeFile()` on the final path. A controlled subprocess test made that difference observable: the test placed a complete report at the destination, injected a writer that persisted only the first 17 bytes and then threw, and ran the real bundled Action. The Action exited 1, but the previous report had been replaced with the partial prefix. That creates an ambiguous CI artifact: a later diagnostic or artifact-upload step can see the expected filename even though VulnFuse never completed the report.

Node documents that `writeFile()` is a convenience method that can perform multiple internal writes and that cancellation is best-effort, with some data likely to remain written. GitHub documents workflow artifacts as the way to persist files after a job and documents `always()` as a step-level mechanism that can run even after failure or cancellation. These are separate mechanisms: `upload-artifact` can faithfully preserve whatever file the producer left, but it cannot determine whether a JSON, SARIF, CSV, Markdown, or HTML report is complete. See Node's [`fsPromises.writeFile()`](https://nodejs.org/api/fs.html#fspromiseswritefilefile-data-options), GitHub's [workflow-artifact overview](https://docs.github.com/en/actions/concepts/workflows-and-actions/workflow-artifacts), and the [status-check function reference](https://docs.github.com/en/actions/reference/workflows-and-actions/expressions#status-check-functions).

Existing libraries confirm the usual design but differ in project fit. Maintained [`write-file-atomic` 8.0.0](https://www.npmjs.com/package/write-file-atomic) uses a temporary file, optional fsync, rename, cleanup, ownership preservation, and same-file write serialization under the ISC license, with one runtime dependency. Its published engine range starts at Node 22.22.2 in the 22.x line, while VulnFuse supports Node 22.12.0. [`atomic-file` 2.1.1](https://www.npmjs.com/package/atomic-file) uses the same basic rename pattern under MIT but brings three dependencies and has not been published for years. VulnFuse already shipped and exercised a dependency-free same-directory writer in its CLI, so sharing and tightening that helper has lower compatibility, dependency, bundle, licensing, and migration cost than adding a general-purpose package to the core and committed Action bundle.

The shared writer now uses a unique exclusively created sibling, flushes it, then calls Node's overwrite-capable `rename`; reported write or rename errors trigger cleanup. POSIX documents same-filesystem destination replacement as atomic, and Microsoft's `MoveFileEx` exposes replacement on Windows. Those platform primitives do not justify a universal durability claim: network filesystems can differ, flushing the file is not the same as synchronizing the containing directory, and a hard process or host failure can leave the temporary sibling. See the Linux [`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html), Node [`rename`](https://nodejs.org/api/fs.html#fspromisesrenameoldpath-newpath), and Microsoft [`MoveFileEx`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw) documentation.

## Why report selection cannot depend on shell globbing

A fresh installation of the public v0.4.6 package failed on a quoted Windows path ending in `*.json`, even though matching report files existed. The CLI passed the literal wildcard to `readFileLimited`, which returned `ENOENT`. The same unquoted text may appear to work in a Unix shell because that shell expands it before VulnFuse starts, so the old behavior made one ordinary multi-report workflow depend on the caller's platform and quoting rules.

This difference is documented rather than hypothetical. PowerShell's native-command design discussion states that Windows does not perform globbing while Linux and macOS do. Mature cross-platform CLIs therefore own this boundary: ESLint documents quoted Node glob syntax to avoid shell-dependent expansion, and Prettier resolves an existing path first and otherwise expands a quoted pattern internally. See [PowerShell issue #14747](https://github.com/PowerShell/PowerShell/issues/14747), the ESLint [CLI reference](https://eslint.org/docs/latest/use/command-line-interface), and Prettier's [file-pattern behavior](https://prettier.io/docs/next/cli/#file-patterns).

Node's built-in `fs.glob` avoids another package on newer runtimes, but it was still experimental in VulnFuse's minimum Node 22.12.0 and became stable in Node 22.17. Raising the runtime floor would impose migration cost unrelated to report correlation, while depending on an experimental filesystem API would weaken the compatibility claim. Among maintained libraries checked on 2026-08-11, `glob` 13.0.6 is BlueOak-1.0.0 with three runtime dependencies and about 1.6 MB unpacked, `fast-glob` 3.3.3 is MIT with five dependencies, and `globby` 16.2.3 is MIT with six. [`tinyglobby` 0.2.17](https://github.com/SuperchupuDev/tinyglobby) is MIT, supports Node 12+, is about 39 KB unpacked, and has two dependencies. It is limited to the CLI package rather than widening the core, browser, or Action surface.

`tinyglobby` depends on `picomatch ^4.0.4`; the lockfile resolved 4.0.5, after the fix for CVE-2026-33672. A local `npm audit` reported no known vulnerabilities at verification time, which is a point-in-time registry result rather than a security guarantee. VulnFuse also treats patterns as explicit filesystem-read authority, matches files only, disables symbolic-link traversal, rejects unmatched patterns, deduplicates overlaps, and applies its 1,000-report limit after expansion. That count does not bound the directory walk itself, so users should avoid patterns rooted at a whole drive or another unnecessarily broad tree. See Node's [`fs.glob` history](https://nodejs.org/api/fs.html#fspromisesglobpattern-options) and the [NVD entry for CVE-2026-33672](https://nvd.nist.gov/vuln/detail/CVE-2026-33672).

The new dependency exposed a release-evidence flaw as well. Running `npm sbom --omit dev` at the monorepo root produced a valid CycloneDX document but omitted `tinyglobby`, `fdir`, and `picomatch`, even though `npm ls --omit=dev` and a clean consumer installation showed that the CLI needs them. A syntactically valid inventory is not enough when its scope differs from the shipped installation. The release workflow therefore installs the exact packed CLI and core archives into an empty directory, generates their SBOM there, and separately generates the Action workspace SBOM. A repository script fails CI or release creation unless each document contains the expected top-level and transitive runtime components. This validates component presence, not universal SBOM completeness or the absence of vulnerable code.

## Why a baseline must expose scanner-set drift

A local reproduction compared one Trivy baseline report with current Trivy plus generic-scanner evidence. VulnFuse correctly classified the generic-only cluster as `new` relative to the supplied evidence, but v0.4.7 gave the normal CLI and Action user no prominent signal that the scanner set itself had changed. Removing Grype similarly produced `updated` and `absent` states without an output-level coverage warning. Those labels can be mechanically correct while still being misread as code introduction or remediation.

Established systems preserve an analysis boundary rather than treating arbitrary result sets as interchangeable. GitHub code scanning requires a category or SARIF `runAutomationDetails.id` for distinct analyses and replaces an earlier set when the same tool/category is uploaded again. DefectDojo documents reimport into the same Test as the recurring-scan workflow; creating a new Test can duplicate findings, and its import history carries commit, build, version, and branch metadata. The OASIS SARIF model likewise provides automation identifiers to group similar runs. See GitHub's [SARIF upload documentation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file#uploading-more-than-one-sarif-file-for-a-commit), DefectDojo's [Test and reimport documentation](https://docs.defectdojo.com/asset_modelling/engagements_tests/os__tests/#reimport), and SARIF 2.1 [`runAutomationDetails`](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

Tool continuity is still not enough. A practitioner reproduced [Grype #2628](https://github.com/anchore/grype/issues/2628) with the same SBOM: version 0.87.0 reported three critical and two high findings, while newer v6-database builds reported none. This is direct evidence that matching filenames, target content, or even a tool name cannot establish comparable coverage across scanner/database changes.

The maintained alternatives solve broader but different problems. GitHub's MIT-licensed CodeQL Action and hosted code-scanning model are GitHub-specific and organize uploaded analyses rather than locally comparing heterogeneous Trivy, Grype, Snyk, OSV, CSV, CycloneDX, and SARIF reports. DefectDojo 3.2.100 was active when checked on 2026-08-11 and is BSD-3-Clause, but adopting its server, database, import model, and Test lifecycle has materially higher operating and migration cost than a local report command. VulnFuse therefore adds no service or dependency: it compares the already normalized per-tool report counts, records added/removed tools and count changes, warns across every output surface, and offers an opt-in CI failure after the report is written.

This is deliberately a narrow guard, not a comparability verdict. Equal tool names and report counts do not prove equal assets, paths, configurations, versions, rules, advisory databases, timestamps, or successful scan completion. Detecting that richer context would require reliable provenance fields the supported formats do not all supply. The structured `scanSetChange` names only what the evidence establishes.

## Why matching scanner names can still hide producer drift

VulnFuse v0.4.15 could call a baseline scan set stable when both sides contained one report named `CodeQL`, even if their SARIF drivers declared `semanticVersion` 2.20.0 and 2.26.2. Finding-level source records sometimes retained a version, but zero-result reports had no finding from which to recover it and `scanSetChange` did not compare it. This made an observable provenance change easy to miss precisely when a changed scanner emitted no findings.

SARIF 2.1 defines both `toolComponent.version` and `semanticVersion`; its result-management guidance says semantic version evidence can be used to restrict results by version or major version. GitHub's maintained [CodeQL Action changelog](https://github.com/github/codeql-action/blob/main/CHANGELOG.md#220---26-jan-2023) also records customer reports of alerts closing and reopening while newer CodeQL versions rolled through hosted runner images. See the [SARIF 2.1 Errata 01 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/sarif-v2.1.0-errata01-complete.pdf).

This is not only a SARIF concern. [Grype issue #2628](https://github.com/anchore/grype/issues/2628) provides a same-SBOM reproduction in which 0.87.0 emitted five critical/high findings and a later v6-database build emitted none. Trivy separately documents mutable [vulnerability and Java databases](https://trivy.dev/docs/latest/configuration/db/). A binary version is therefore useful provenance, but it cannot prove that advisory data, rules, configuration, target identity, or runtime conditions stayed fixed.

Pinning scanner binaries and Actions remains the lowest-cost preventive control, but it cannot retrospectively establish what an already-supplied report embedded, and mutable databases require separate pinning or retention. GitHub CodeQL Action (MIT) is the correct hosted CodeQL integration but not a heterogeneous local baseline comparator. DefectDojo 3.2.100 (BSD-3-Clause) and Dependency-Track 5.0.4 (Apache-2.0) provide maintained server, database, ingestion, inventory, and policy lifecycles, with materially higher operating and migration cost. Microsoft SARIF SDK 5.6.0 uses an MIT license and provides a comprehensive .NET SARIF model, but it does not compare Grype, CycloneDX, Trivy, and CSV provenance or fit the existing browser-compatible TypeScript core. These projects and versions were checked on 2026-08-12.

VulnFuse therefore reuses version fields already present in supported inputs, stores a sorted set per tool and the count of reports that lacked version evidence, and extends the existing scan-set warning and post-write gate. The implementation adds no runtime dependency, service, network request, or version-registry lookup. It compares literal evidence only: no lexical or semantic ordering, upgrade/downgrade label, freshness claim, or safety inference is made. Equal embedded versions still do not prove comparable scans, and missing evidence stays missing rather than being inferred from filenames or logs.

The end-to-end acceptance used a pinned public [CodeQL C# SARIF file](https://github.com/hohn/codeql-intro-csharp/blob/b2049c92852737c1b91af5a58f3601e0f83a8cb4/csharp-sqli.sarif), generated by CodeQL 2.19.2 with four results. The 11,224-byte download had SHA-256 `FF74C3F5D692EDAABB4842B8520F11726A3B4A7E469F53B451EA58BED7B58926` on 2026-08-12. A derived current copy changed only `run.tool.driver.semanticVersion` to 2.26.2. CLI, Action, and browser comparisons kept all three correlated clusters unchanged while exposing the literal version drift; the opt-in gate wrote the full result before returning failure. This derived pair tests provenance handling, not an actual rescan or a claim that the two CodeQL versions behave differently on that target.

## Why matching versions can still hide a different SARIF analysis category

VulnFuse v0.4.16 compared one pinned Microsoft SARIF Tutorials
[`automation-details.sarif`](https://github.com/microsoft/sarif-tutorials/blob/819b0f62f47ecde9a8f24dfc387c41926f5edabe/samples/3-Beyond-basics/automation-details.sarif)
file with a derived copy whose only semantic change replaced `master` with
`release` in `run.automationDetails.id`. Both files declared the same
`CodeScanner` tool and zero results. The old CLI returned 0 and
`scanSetChange.detected: false`. The 582-byte CC-BY-4.0 source fixture had
SHA-256 `E1BF3EBA8FD15747CAAB6E47BF3FC4F969BD0EC05B85BD1CD01219B5DC0CF85F`;
the derived copy had SHA-256
`C9181B9DE88C61E75225753F776B35095995F5AB0B135891E876D264D150A33D`
on 2026-08-12. The external fixture is not copied into this Apache-2.0
repository.

The field has documented identity semantics, but it is not a coverage oracle.
GitHub's current [SARIF support reference](https://docs.github.com/en/enterprise-cloud@latest/code-security/reference/code-scanning/sarif-files/sarif-support#runautomationdetails-object)
interprets the id as `category/run-id`: everything before the final `/` is the
category, while an id with no slash has only a run id and no category. GitHub
uses categories to distinguish the same tool and commit when different
languages or repository parts were analyzed. The CodeQL CLI likewise
recommends [`--sarif-category`](https://docs.github.com/en/code-security/codeql-cli/codeql-cli-manual/database-interpret-results#--sarif-categorycategory)
and says distinct analysis variants should use different values while the same
variant should keep a stable value across code revisions. OASIS SARIF 2.1
defines `runAutomationDetails.id` as a hierarchical run identifier; VulnFuse
uses GitHub's narrower, documented last-slash interpretation and does not infer
scope from other path components.

This boundary causes real workflow friction. In
[`github/codeql-action#1058`](https://github.com/github/codeql-action/issues/1058),
a user had a successful analyzer artifact that did not appear in code scanning;
maintainers discussed splitting the analysis and assigning different categories
to each slice. The report is not proof of VulnFuse adoption or of every missing
result cause, but it independently shows that category identity matters in an
ordinary multi-analysis workflow.

Maintained alternatives cover adjacent jobs. GitHub's MIT-licensed CodeQL
Action and `upload-sarif` establish hosted upload identity, but do not guard a
local baseline across SARIF, SBOM, VEX, and CSV inputs. Microsoft's MIT-licensed
[`sarif-tools` 3.0.5](https://github.com/microsoft/sarif-tools/releases/tag/v3.0.5)
compares issue histograms: its real `sarif diff` command reported no changes and
returned 0 on the category-only pair. In one clean Windows Python 3.13 virtual
environment it installed 4,889 files totaling 150,518,051 bytes because its
general report suite includes plotting and document dependencies; that local
measurement is not a universal install-size benchmark. Microsoft's maintained
MIT-licensed [SARIF SDK/Multitool 5.6.0](https://github.com/microsoft/sarif-sdk/releases/tag/v5.6.0)
provides a comprehensive .NET model, validation, and transformation surface,
but not VulnFuse's heterogeneous post-write gate. A hosted vulnerability
management server adds storage, service, and migration cost for a check that
can use evidence already present in the input.

VulnFuse therefore adds no runtime dependency, service, or network request. It
records a sorted category set and uncategorized-run count per SARIF tool,
preserves zero-result runs and VulnFuse JSON re-ingestion, and extends the
existing warning and post-write gate. Headless browser acceptance exposed a
second v0.4.16 defect: the Web workbench hid its entire result/export section
when all loaded reports had zero findings, including this category warning.
The browser now renders the zero-count review and export controls whenever a
report is loaded. A category change proves only that the producer/user supplied
different identity evidence. Equal categories do not prove identical files,
languages, targets, rules, configuration, databases, or successful completion;
changed categories do not prove that one scan was broader, newer, or safer.

## Why SARIF suppression cannot be discarded or blindly trusted

The public v0.4.8 CLI parsed all nine results in Microsoft's [`Suppressions.sarif`](https://github.com/microsoft/sarif-tutorials/blob/main/samples/Suppressions.sarif) sample, but exposed none of their `suppressions` metadata. Accepted or in-source suppressions therefore remained indistinguishable from active findings and could trip `--fail-on`; at the same time, the original kind, review status, and justification disappeared from the canonical audit trail.

SARIF 2.1 defines suppression as review state, not evidence deletion. The OASIS specification says a result is not suppressed when the property is absent, `null`, or an empty array, and explains that suppression information supports compliance review. Microsoft's current [viewer guidance](https://github.com/microsoft/sarif-tutorials/blob/main/docs/Displaying-results-in-a-viewer.md) and maintained [SARIF SDK](https://github.com/microsoft/sarif-sdk/blob/main/src/Sarif/Core/Result.cs) treat a result as not suppressed when any suppression is `underReview` or `rejected`; otherwise a non-empty list is suppressed. CodeQL's official [SARIF output documentation](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/sarif-output) also shows an `inSource` suppression without a status, so missing status cannot safely be treated as malformed.

Practitioners need the record even when it is excluded from an active queue. [DevSkim issue #693](https://github.com/microsoft/DevSkim/issues/693) asks for suppressed findings to remain in SARIF precisely so reviewers can audit what was omitted; reconstructing that evidence after export is fragile. GitHub code scanning documents only a [supported subset of SARIF properties](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning), so a local cross-scanner tool cannot assume that a hosted alert lifecycle will preserve or apply every suppression field in the same way.

Maintained alternatives address adjacent layers but not this local composition gap. Microsoft's SARIF SDK 5.6.0 is a maintained MIT-licensed .NET object model; using it would add a runtime/platform boundary to a TypeScript parser. DevSkim 1.0.90 is maintained and MIT-licensed but is a scanner, not a heterogeneous correlation layer. GitHub's CodeQL Action is maintained and MIT-licensed but targets GitHub's hosted analysis model. DefectDojo 3.2.100 is maintained under BSD-3-Clause and provides a server/database import lifecycle; adopting it has materially higher operating and migration cost than preserving disposition in an offline command. These versions were checked on 2026-08-11.

VulnFuse therefore adds no dependency or service. It preserves valid source suppression objects, keeps malformed or contested values active with a warning, and marks a cluster effectively suppressed only when every member is effectively suppressed. Severity gates consume active-only counts; total counts and source justifications remain visible. This trusts the producer's metadata and does not prove a false positive, authenticate risk acceptance, or mutate GitHub/DefectDojo alert state.

## Why a SARIF pass is not a vulnerability

The public v0.4.9 CLI treated every SARIF `results[]` entry as an active finding. Against Microsoft's pinned [BinSkim `gcc.fortified.sarif` fixture](https://github.com/microsoft/binskim/blob/a971ef1b4c5e07ea9f776b607d449646fa830044/src/Test.FunctionalTests.BinSkim.Driver/BaselineTestData/Expected/gcc.fortified.sarif), it retained seven records and classified all seven as active: five `kind: pass`, `level: none` rule outcomes and two failures. A `--fail-on info` gate therefore failed even though five of the seven source records explicitly said that the rule found no problem. The downloaded 18,576-byte fixture had SHA-256 `BC08B48C6363EB51CF47E366A40ED32EA3BA5C77CC6BE34335D5B08D8952B683` during the 2026-08-11 reproduction.

That behavior conflicts with the [SARIF 2.1 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#def_result_kind). `pass` means the rule was evaluated and no problem was found, `informational` does not indicate a problem, and `notApplicable` means the rule did not apply. `open` and `review` require review, while `fail` indicates a problem and is the default when `kind` is omitted. The same specification constrains non-fail outcomes to `level: none`, and Microsoft's maintained [viewer guidance](https://github.com/microsoft/sarif-tutorials/blob/main/docs/Displaying-results-in-a-viewer.md) separates these kinds from ordinary fail results.

The impact is not theoretical. In [sarif-converter issue #39](https://gitlab.com/ignis-build/sarif-converter/-/issues/39), a practitioner reported that OpenSCAP pass and skipped checks became vulnerabilities because the converter ignored `result.kind`. Another published [OpenSCAP-to-GitHub workflow](https://candrews.integralblue.com/2023/09/scap-security-and-compliance-scanning-of-docker-images-in-github-actions-and-gitlab-ci/) deleted `pass`, `informational`, and `notApplicable` results with `jq` before upload. That workaround avoids false alerts but permanently discards evidence that a check ran or did not apply.

GitHub's current [supported SARIF subset](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) does not list `result.kind`; it describes supported `results[]` as alerts. VulnFuse therefore cannot safely emit non-finding clusters as ordinary GitHub-bound results and assume the host will honor kind. It excludes them from exported `results[]` but retains the complete clusters under `run.properties.nonFindingClusters` (or baseline `nonFindingItems`) so the local audit artifact does not lose them.

Maintained alternatives address narrower or heavier layers. Microsoft's SARIF SDK 5.6.0 is an MIT-licensed .NET object model and can parse the standard, but adopting it would add a runtime boundary without supplying VulnFuse's heterogeneous correlation, gates, or review surfaces. JetBrains' MIT-licensed `sarif-converter` is a Go conversion utility oriented around GitLab formats; it is not a local cross-scanner correlation layer. GitHub code scanning is hosted and GitHub-specific. DefectDojo 3.2.100 is a BSD-3-Clause server/database vulnerability-management system with materially higher deployment and migration cost. None justifies a new runtime dependency for a seven-value field that the existing defensive SARIF parser can handle directly.

VulnFuse now keeps three explicit dispositions: active, effectively suppressed, and non-finding. It marks a cluster non-finding only when every member is a valid non-finding result, lets any active actual-finding record keep the cluster active, and warns while keeping unknown, non-string, or contradictory kind/level combinations gate-eligible. This fixes the observed false-positive gate without claiming that producer metadata is true: VulnFuse does not rerun the rule, establish that a target was actually scanned, or prove applicability.

## Why a valid SARIF file can still be an incomplete scan

The public v0.4.12 CLI silently accepted two materially different failed-run files. Microsoft's pinned [`Catastrophic execution error.sarif`](https://github.com/microsoft/sarif-tutorials/blob/819b0f62f47ecde9a8f24dfc387c41926f5edabe/samples/ExceptionalConditions/Catastrophic%20execution%20error.sarif) sample declared `executionSuccessful: false`, reported an error-level out-of-memory notification, and omitted inline results; `inspect` returned 0 with no warnings. A pinned [Zypheron combined scan](https://github.com/KKingZero/Zypheron-CLI/blob/57e023e0e26e1cd10962524de4cbf205bf895b94/zypheron-go/internal/export/combined-scans.sarif) retained two findings while both invocations declared failure; v0.4.12 again returned 0 with no warnings. The downloaded files were 614 and 3,126 bytes with SHA-256 `D110486654A984752D8B6E54485FBBF4BFC68B75E96B8E7D493081DFD6C55BD7` and `6E9A6719394416C774AEB8EE6576C3D9752DE5706FC900E0CB29007785C3E428`, respectively, during the 2026-08-12 reproduction.

The [OASIS SARIF 2.1 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) defines the mechanism precisely. A false `executionSuccessful` means the engineering system knows the analysis failed. An error-level tool or configuration notification means consumers cannot assume every rule ran against every target. Null or absent `results` means the tool failed to start or begin analysis unless results are externalized. These are run-completeness signals, not vulnerability results or schema errors.

Rejecting the whole file would lose useful evidence. A [GitLab SARIF importer change](https://gitlab.com/gitlab-org/security-products/analyzers/report/-/merge_requests/52) documents a Semgrep customer who needed partial results when one file caused an error; GitLab changed from fatal rejection to logging the notification. A practitioner separately described Kubernetes-oriented [SARIF output as incomplete or flaky](https://www.reddit.com/r/devops/comments/17hsqbe/k8s_sast_dilemma_help/). The product inference is an explicit two-part policy: always retain the available inline findings and warnings, while offering an opt-in post-write gate for workflows that require comprehensive scans.

Maintained alternatives cover adjacent boundaries. Microsoft's MIT-licensed SARIF SDK/Multitool 5.6.0 performs schema and object-model work but requires the .NET tool/runtime, and `executionSuccessful: false` is valid SARIF rather than a schema violation. Anchore's Apache-2.0 [`sarif-validator`](https://github.com/anchore/sarif-validator) runs a Node 21 Docker image containing Jest and the beta `@microsoft/jest-sarif`; it validates schema rather than applying a cross-report completeness policy. GitLab's importer is tied to GitLab analyzers. DefectDojo's maintained SARIF reimport requires a server/database and deliberately keeps one tool per Test so missing findings can be interpreted within that tool's lifecycle. None replaces a lightweight local gate that correlates heterogeneous evidence and preserves its output before failing.

VulnFuse therefore adds no dependency or service. It inspects only already-loaded JSON, never executes a recorded command line, does not fetch external properties, preserves selected per-run health counts and warnings, and lets CLI/Action users opt into `fail-on-incomplete`. This still cannot prove coverage: a producer can lie about success or omit invocation metadata, and the absence of a warning does not establish that the intended targets, rules, versions, or configuration were actually scanned.

## Why a SARIF file path can lose its source-root prefix

The public v0.4.13 parser read `artifactLocation.uri` but ignored both
`artifactLocation.uriBaseId` and `run.originalUriBaseIds`. Against Microsoft's
pinned [`OriginalUriBaseIds.sarif`](https://github.com/microsoft/sarif-tutorials/blob/819b0f62f47ecde9a8f24dfc387c41926f5edabe/samples/OriginalUriBaseIds.sarif)
sample, `inspect` returned three findings with no warning, while TUT1002 entered
the canonical model as `io/kb.c`. The sample declares that URI under `SRCROOT`,
whose portable relative segment is `src/`; another scanner reporting
`src/io/kb.c` would therefore receive a different file asset. In VulnFuse's
default instance scope, different assets are a hard correlation blocker rather
than a small score difference. The downloaded CC-BY-4.0 sample was 2,992 bytes
with SHA-256
`48C63F0FA36C72724CE67CCCC1783122E83AF9805176E041A127468F3A3C7A4A`
during the 2026-08-12 reproduction. It is used as external acceptance evidence,
not copied into the Apache-2.0 repository fixtures.

The behavior is defined by the standard, not inferred from one producer. OASIS
SARIF 2.1 plus Errata 01 specifies consumer resolution through configured
mappings and then `originalUriBaseIds`, permits a top-level absolute URI to be
removed for privacy and deterministic output, prohibits loops and `..` path
segments, and requires URI-base path segments to end in `/`. GitHub's current
[SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
documents the same relative-root structure, while the CodeQL CLI
[SARIF output contract](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli/sarif-output)
says `uriBaseId` is generated when a file is relative to a known abstract
location such as the source root. See the OASIS
[URI-base sections](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).

Independent implementation reports show recurring workflow cost:

- [SARIF VS Code extension #644](https://github.com/microsoft/sarif-vscode-extension/issues/644)
  reports that every `%SRCROOT%` finding becomes “File not found” when a
  monorepo workspace root differs from the analyzed subfolder.
- [`sarif-rs` #986](https://github.com/psastras/sarif-rs/issues/986) requests a
  source-root option because CodeQL paths cannot be opened when formatting a
  SARIF file outside the analyzed checkout.
- [CodeQL Action #2215](https://github.com/github/codeql-action/issues/2215)
  reports wrong/file-not-found paths with multiple URI bases and describes
  preprocessing the report as a workaround.
- [SARIF SDK #2969](https://github.com/microsoft/sarif-sdk/issues/2969) reports
  empty source hashes when one streaming path ignores `originalUriBaseIds`,
  even though the post-processing path resolves them.
- Jenkins [analysis-model #1418](https://github.com/jenkinsci/analysis-model/issues/1418)
  was fixed after users reported source files missing when reports and builds
  lived in different directories or machines.

These reports do not establish one universal checkout-mapping policy. They do
establish that ignoring the field loses information and pushes users toward
manual path rewriting.

Maintained alternatives were checked on 2026-08-12. Microsoft's SARIF SDK
5.6.0 is an MIT-licensed comprehensive .NET model and toolchain, but importing
that runtime does not fit VulnFuse's browser-compatible TypeScript core.
`sarif-rs` is maintained, MIT-licensed Rust; its open source-root issue shows
that adopting a separate formatter would not remove the mapping gap. Jenkins
analysis-model 14.16.0 is maintained and MIT-licensed Java infrastructure that
solves the problem inside Jenkins rather than as a drop-in local correlation
library. GitHub's maintained MIT-licensed CodeQL Action is the right hosted
upload path for GitHub users, but it is not a local heterogeneous correlator and
its URI-base issue remains open. None justifies a new service, runtime, or
dependency for the bounded prepend algorithm already specified by SARIF.

VulnFuse therefore resolves only the portable part of the chain. It validates
and prepends relative URI-base segments, stops at an omitted/redacted or
absolute top-level root, and never copies that absolute producer path into the
canonical file identity. Unknown, circular, malformed, traversal-bearing, or
overlong chains preserve the raw location and warn. The original URI, base id,
and successful resolution boundary remain as source properties. No file is
opened, no URI is fetched, and no local workspace root is guessed.

That last boundary is material. OASIS gives an explicit user mapping priority,
but VulnFuse does not yet expose such a mapping. If `%SRCROOT%` has no usable
relative segment in the report, the tool cannot know whether it means the
repository root, a monorepo subdirectory, a generated tree, or another machine.
This release improves portable correlation; it does not claim complete absolute
URI resolution, source navigation, symlink equivalence, or filesystem identity.

## CycloneDX XML without a conversion step

VulnFuse v0.4.14 accepted CycloneDX JSON but rejected an equivalent XML VDR or
VEX document before parsing. This is a format-compatibility gap, not a request
for a second semantic model. CycloneDX 1.7.1 is current as checked on
2026-08-12, and the specification registers both
`application/vnd.cyclonedx+json` and `application/vnd.cyclonedx+xml`, with
`bom.json`/`*.cdx.json` and `bom.xml`/`*.cdx.xml` as recognized file patterns.
The official vulnerability fixtures publish the same evidence model in XML.
See the CycloneDX [specification overview](https://cyclonedx.org/specification/overview/),
[repository](https://github.com/CycloneDX/specification), and pinned
[1.4 vulnerability fixture](https://github.com/CycloneDX/specification/blob/970eeb2995c16ea95124a224b7defc351dd563bd/tools/src/test/resources/1.4/valid-vulnerability-1.4.xml).

The format occurs in ordinary build pipelines. The maintained Apache-2.0
CycloneDX Maven plugin 2.9.3 emits and attaches both XML and JSON, while its
older 1.x line supported XML only. The maintained Apache-2.0 Gradle plugin
3.4.1 generates `bom.json` and `bom.xml` by default. Syft also exposes a
`cyclonedx-xml` output, and a practitioner report in
[Syft #4363](https://github.com/anchore/syft/issues/4363) shows a real XML
producer/consumer compatibility failure. That issue does not prove every XML
BOM is problematic; it demonstrates that asking users to swap serialization
does not remove version and parser interoperability costs.

Maintained alternatives were checked before implementation. The Apache-2.0
[CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) can convert XML to
JSON accurately and remains the better choice for full format conversion, but
it adds a .NET binary or container plus an extra file/pipe step to every local
and CI workflow. The Apache-2.0 `@cyclonedx/cyclonedx-library` 10.1.1 is current
and provides models, normalizers, serializers, and validators; it does not
provide a universal XML deserializer and its unpacked npm package is about 5.2
MB. `fast-xml-parser` 5.10.1 is MIT and browser-compatible, but brings five
runtime dependencies and about 1.3 MB unpacked; older 5.x releases below 5.3.6
were affected by entity-expansion denial of service
([CVE-2026-26278](https://github.com/advisories/GHSA-jmr7-xgp7-cmfj)).

The selected `@rgrove/parse-xml` 4.2.3 parser is actively maintained,
ISC-licensed, browser-compatible, zero-dependency, and about 380 KB unpacked.
It deliberately does not load external DTDs or resolve custom DTD entities.
VulnFuse adds a stricter boundary by rejecting every `DOCTYPE`, then converts
only the CycloneDX fields its existing JSON parser already understands. The
same canonical parser therefore decides identifiers, PURLs, affected targets,
severity, remediation, VEX evidence, and safe references for both formats.
The complete ISC notice ships with packages and the bundled Action archive.

This is not full XML or CycloneDX validation. Unknown extensions are ignored;
XSD constraints and signatures are not checked; no schema, entity, BOM-Link,
or advisory URL is fetched. Element nesting is capped at 100. Parsing is
non-streaming and adds an in-memory tree on top of the already-buffered report,
within the existing per-report byte limit. Users who need lossless conversion
or formal schema validation should keep the official CycloneDX tooling in that
part of the pipeline.

## Release bytes that consumers can actually verify

The public v0.4.17 release exposed a failure in its own download acceptance.
Its five artifacts and `SHA256SUMS.txt` downloaded correctly, and the digests
were accurate, but every manifest entry named `release/<asset>`. GitHub Release
assets are downloaded under their individual basenames, so running the standard
`sha256sum -c SHA256SUMS.txt` beside all six downloads failed 5/5 with "No such
file or directory." Removing the workflow-only directory prefix made the same
digests pass. The reproduction and acceptance criteria are public in
[issue #55](https://github.com/CAOShurong/vulnfuse/issues/55).

This is an ordinary distribution contract, not a VulnFuse-specific checksum
interpretation. GNU Coreutils checks the filenames recorded in a checksum file.
Bitcoin Core's maintained release process explicitly removes build-output
subdirectories so downloads can be verified without reconstructing directory
structure. HashiCorp's Terraform verification guide likewise expects the
downloaded archive name to match a flat `SHA256SUMS` entry; it also demonstrates
the confusing missing-file output when only one of many listed archives is
present. Users have independently reported needing to strip server paths from
published checksum names before verification. See the
[GNU Coreutils manual](https://www.gnu.org/software/coreutils/manual/coreutils.html),
[Bitcoin Core release process](https://github.com/bitcoin/bitcoin/blob/master/doc/release-process.md#after-6-or-more-people-have-guix-built-and-their-results-match),
[Terraform verification guide](https://developer.hashicorp.com/terraform/tutorials/cli/verify-archive),
and the practitioner report about
[release paths embedded in `sha256sum.txt`](https://www.reddit.com/r/voidlinux/comments/ltqi3b/issues_verifying_the_new_20210218_current_release/).

The second failure was more important than path convenience. Both
`gh release verify v0.4.17` and `gh release verify-asset` exited 1 because the
tag workflow created no attestation. An unauthenticated checksum detects changed
bytes only if the consumer already trusts the manifest. GitHub's current
artifact-attestation design binds artifact names and digests to a signed
in-toto/SLSA provenance statement, stores the statement through the repository
attestations API, and verifies it with GitHub CLI. Public repositories can use
the service on current GitHub plans. This establishes workflow provenance; it
does not establish that the source, runner, dependencies, or executable are
safe. See GitHub's primary documentation for
[generating attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations),
[release verification](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/verify-release-integrity),
and the MIT-licensed
[`actions/attest` implementation](https://github.com/actions/attest).

Maintained alternatives were checked on 2026-08-12. GoReleaser 2.17.1 is an
active MIT release system that emits flat checksums, Sigstore bundles, SBOMs,
and attestations. Its Linux packages were roughly 24-28 MB and adopting it would
replace a working Node/npm-specific pack-and-SBOM workflow with another release
configuration and toolchain. It is a sound choice for broader multi-platform
binary release automation, but disproportionate for correcting six filenames.
The active MIT `softprops/action-gh-release` 3.0.2 uploads releases on Linux,
Windows, and macOS, but does not itself authenticate a checksum manifest or
generate build provenance. GitHub's Release Asset API now exposes a SHA-256
digest, but consuming it requires an API/client and does not create an offline
manifest. `gh attestation verify` is the right online consumer for an
`actions/attest` statement, but requires a recent CLI and network access.

VulnFuse therefore keeps the existing GitHub-hosted release path without adding
a paid service or shipped runtime dependency. It adds a dependency-free Node
checksum writer already supported by the repository's Linux and Windows
runtimes, then composes it with the official `actions/attest` 4.2.2 action
pinned to its verified release commit. The attestation adds one network/OIDC
step and makes GitHub's attestation service another release-time failure
surface; offline checksum use remains available. Pinning reduces action-version
drift but is not evidence that the action or runner is vulnerability-free. The
writer sorts controlled portable asset basenames, streams SHA-256 calculation,
rejects an empty artifact directory, and excludes the manifest itself on rerun.
Linux CI checks real packed npm artifacts; Windows CI checks real SARIF and
OpenVEX fixtures; the tag workflow checks and attests the exact CLI/core
packages, Action archive, and CycloneDX SBOMs that it then publishes.

Public v0.4.18 acceptance exposed an important command boundary after those
controls shipped. The flat manifest passed 5/5, all six local files matched the
GitHub Release Asset API digests, and strict `gh attestation verify` succeeded
when constrained to this repository, `.github/workflows/release.yml`,
`refs/tags/v0.4.18`, and GitHub-hosted runners. However, `gh release verify` and
`gh release verify-asset` both exited 1 with "no attestations for tag." The
repository API reported immutable releases disabled and the release itself as
`immutable: false`. GitHub documents those commands specifically for immutable
release attestations; they are not aliases for an ordinary `actions/attest`
statement. See GitHub's
[immutable-release verification documentation](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/verify-release-integrity)
and [issue #57](https://github.com/CAOShurong/vulnfuse/issues/57).

VulnFuse therefore documents the narrower command that was actually observed:
`gh attestation verify` with signer-workflow, source-ref, and hosted-runner
constraints. The repository does not enable immutable releases as part of this
change. That setting would alter repository policy and future release mutation
rules; it is not necessary to verify the SLSA statement already attached to the
assets and is not silently presented as enabled.

## SARIF rule-tag ingestion-limit research (v0.4.20)

GitHub's current
[SARIF support reference](https://docs.github.com/en/enterprise-cloud@latest/code-security/reference/code-scanning/sarif-files/sarif-support)
lists 20 tags per rule as the hard maximum and says only 10 are retained. Its
[upload troubleshooting guide](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/troubleshoot-sarif-uploads/results-exceed-limit)
names `Analysis SARIF file rejected due to rule tag limits` and tells generator
authors to emit fewer than 10 tags when repairing that failure. The same
reference makes clear that code scanning uses rule tags for filtering, while
arbitrary VulnFuse result properties are not part of GitHub's supported display
contract.

VulnFuse 0.4.19 had an unbounded producer-side path: `security`, the finding
kind, and every correlated identifier became rule tags. A local reproduction
using the real Trivy fixture plus 30 valid aliases emitted 32 tags for one rule.
The complete 30-identifier array was already duplicated in the result's
VulnFuse properties, so limiting the filter/display copy does not require
discarding the underlying evidence.

Maintained alternatives do not remove the generator's responsibility:

- `github/codeql-action/upload-sarif` is an active MIT upload client. It can
  report GitHub's validation failure, but it cannot choose which VulnFuse alias
  tags are expendable after generation.
- Microsoft SARIF Multitool 5.5.0 is an active MIT general-purpose transformer.
  Adding a separate transform step and runtime would increase installation and
  migration work without a VulnFuse-specific evidence-retention policy.
- `sarif-tools` 3.0.5 is an MIT Python 3.8+ inspection/transformation suite. It
  adds a Python dependency and likewise has no basis for deciding which
  VulnFuse identifiers are retained elsewhere.
- `advanced-security/filter-sarif` is a maintained Apache-2.0 Action for
  path/severity result filtering, not per-rule alias-cardinality repair.

The selected fix therefore adds no dependency or service. It emits nine tags,
the stricter directly documented troubleshooting boundary: `security`, the
finding kind, then up to seven identifiers ordered by relationship priority and
value. `vulnfuseOmittedIdentifierTagCount` makes the reduction explicit, while
`results[].properties.identifiers` retains the complete set. Core,
separate-process CLI, and bundled Action tests cover the same alias-rich case.
This prevents one documented rejection mode; only GitHub's ingestion service
can decide whether a complete upload satisfies every current limit, permission,
and product-availability rule.

## Hosted SARIF text-limit research (v0.4.21)

The general SARIF 2.1.0 schema and hosted ingestion contracts are different
layers. The current [SARIF JSON schema](https://json.schemastore.org/sarif-2.1.0.json)
defines `reportingDescriptor.name` and message text as strings without
`maxLength`. GitHub's current
[supported SARIF subset](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
limits a rule name to 255 characters and each rule short/full description to
1,024. GitLab's
[SARIF ingestion documentation](https://docs.gitlab.com/user/application_security/detect/sarif/)
uses those limits and also limits `result.message.text` to 1,024; an over-limit
string skips a result, and a drop rate above 50% aborts the scan. These are
platform contracts, not conclusions implied by standards validity.

VulnFuse 0.4.20 copied identifier, title, and description data into those fields
without a bound. A real CLI reproduction produced a 307-character rule name,
1,311-character short description, 1,517-character full description, and
1,357-character result message. The file passed both the generic JSON schema
through Ajv 8.17.1 and Microsoft SARIF Multitool 5.6.0 validation with zero
reported errors. It was not uploaded because that would publish a synthetic
security analysis; the documented limits and local false-negative validation
are sufficient to justify a producer-side preflight.

Reviewing both exporters exposed a second failure path. Plain SARIF received the
v0.4.20 nine-tag guard, but baseline-comparison SARIF kept a duplicate rule
builder and could still emit every correlated identifier as a tag. Sharing a
single rule builder fixes the observed divergence rather than copying another
patch into both paths.

Maintained alternatives remain useful but do not replace the producer fix:

- `github/codeql-action/upload-sarif` is an active MIT upload client. It adds
  GitHub workflow integration and fingerprints, but waiting for a hosted upload
  to reject or degrade generated data is later and more expensive than emitting
  compatible fields at the source.
- Microsoft SARIF Multitool 5.6.0 is an active MIT validator and transformer,
  distributed through a small npm launcher plus a platform-specific binary. It
  accepted the reproduced artifact and would add a separate normalization step
  without knowing where VulnFuse retains original evidence.
- `sarif-tools` 3.0.5 is an MIT Python 3.8+ inspection/transformation suite.
  It adds a Python runtime and workflow step, and generic format handling cannot
  choose VulnFuse's evidence-preservation fields automatically.
- `advanced-security/filter-sarif` is a maintained Apache-2.0 Action for
  filtering results by paths or severity, not bounding rule/result display text.

The selected implementation adds no dependency, service, network call, or user
configuration. It conservatively counts UTF-16 code units, reserves space for
an ellipsis, and iterates full Unicode code points so a surrogate pair is never
split. Exact originals remain under explicitly named VulnFuse properties only
when a field is shortened. Core, separate-process CLI, committed Action, and
baseline-comparison tests use a Trivy-shaped report at the Unicode boundary.
This improves GitHub/GitLab fit; it is not an exact emulator or a guarantee that
an upload satisfies every permission, size, count, URI, or evolving product
rule.

## Locationless SARIF visibility research (v0.4.22)

Standards validity and GitHub code-scanning visibility differ. SARIF 2.1 says a
result `locations` array should be present, but explicitly permits rare results
without a location when none can be specified. GitHub's current supported-SARIF
reference is stricter: at least one location is required for code scanning to
display a result, and a repository-relative `artifactLocation.uri` is
recommended. See the [OASIS SARIF 2.1 result location contract](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#def_result_locations)
and GitHub's [SARIF support reference](https://docs.github.com/en/enterprise-cloud@latest/code-security/reference/code-scanning/sarif-files/sarif-support#result-object).

The public v0.4.21 CLI reproduced the gap from formats VulnFuse advertises: the
OpenVEX fixture produced three SARIF results with zero `locations`, and the
CycloneDX fixture produced one with zero. Both outputs passed the generic SARIF
2.1 JSON schema and Microsoft SARIF Multitool 5.6.0 with zero validation errors.
That is expected standards behavior, but those package findings do not satisfy
GitHub's display contract. No synthetic analysis was uploaded to code scanning;
the platform requirement and a real independent rejection are enough to justify
an opt-in producer fix without publishing misleading alerts.

The independent practitioner case is concrete. Apache-2.0
[`proofhouse/gomodscan`](https://github.com/proofhouse/gomodscan) reported that
every upload was rejected with `expected a physical location`; its May 2026
[fix](https://github.com/proofhouse/gomodscan/pull/1) anchors each finding to the
real `vendor/modules.txt` line the scanner already reads. The repository was
active when checked on 2026-08-12. VulnFuse cannot infer an equivalent file from
arbitrary OpenVEX, CycloneDX, SBOM, image, or mixed-report evidence, so silently
choosing `package-lock.json` or another ecosystem-specific file would invent
provenance and fail on many repositories.

Maintained alternatives address adjacent layers:

- GitHub's MIT-licensed `github/codeql-action` is the correct upload client and
  can add fingerprints, but it cannot infer a truthful repository file for
  locationless package evidence. It also ties the workflow to GitHub's hosted
  service rather than repairing the producer artifact for other consumers.
- Microsoft SARIF SDK/Multitool 5.6.0 is maintained and MIT-licensed. It adds a
  .NET/platform binary and a separate transform step, and generic validation
  accepted the reproduced locationless output because the SARIF standard
  permits it.
- `gomodscan` demonstrates the best answer when a scanner owns a real source
  mapping: emit the exact file and line. Its Go-specific `vendor/modules.txt`
  solution is not reusable for VulnFuse's heterogeneous SARIF, SBOM, and VEX
  inputs.

The selected design therefore adds no dependency, service, upload, or operating
cost. The caller may explicitly supply one syntactically safe repository-relative
URI. VulnFuse attaches its line 1 only to results lacking a physical URI, keeps all
scanner locations untouched, and marks the substitution as
`user-supplied-fallback`. Plain and baseline exporters share the behavior. The
path validator rejects absolute/schemed values, traversal, backslashes, empty
segments, queries, fragments, whitespace/control characters, invalid percent
encoding, and encoded separators. It does not open the file or prove that it is
tracked in the uploaded commit. This closes a daily workflow gap while keeping
the causal claim honest: the fallback is a navigation anchor, not evidence that
the finding originated in that file, and only a real hosted upload can prove
acceptance.

## Portable source-report identity research (v0.4.23)

The public v0.4.22 README says identical input and policy produce stable finding
and cluster IDs. The bundled Action nevertheless passed each absolute
`@actions/glob` match into the parser as the report name; CLI glob expansion did
the same. That name was exported in `sourceReports` and included in every source
finding identity. Running byte-identical OpenVEX input under `workspace-a` and
`workspace-b` produced different output hashes, all three source finding IDs,
all three cluster IDs, and all SARIF fingerprints. The generated artifact also
persisted the full Windows drive, scratch, checkout, and workspace path.

This is a documented portability and privacy defect, not a preference. OASIS
[SARIF 2.1](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
warns that absolute paths can reveal sensitive information and its deterministic
log guidance excludes machine-dependent invocation data. GitHub's
[SARIF alert-limit troubleshooting](https://docs.github.com/code-security/code-scanning/troubleshooting-sarif-uploads/results-exceed-limit)
identifies temporary directories and environment-dependent paths as causes of
unstable alert identity and asks tool vendors to fix producer output. The
[Reproducible Builds build-path guidance](https://reproducible-builds.org/docs/build-path/)
likewise recommends removing or normalizing filesystem roots embedded in
artifacts.

Maintained alternatives address adjacent layers but cannot repair the producer
identity after VulnFuse has hashed it:

- `github/codeql-action/upload-sarif` is maintained and MIT-compatible. Its
  `checkout_path` input relativizes SARIF artifact locations before upload, but
  it does not know that VulnFuse's custom `sourceReports[].name` and precomputed
  fingerprints contain an input report path. It also cannot repair offline JSON,
  CSV, Markdown, or HTML exports.
- Microsoft SARIF SDK/Multitool 5.6.0 is maintained and MIT-licensed. It can
  validate and transform generic SARIF, but generic validation accepts custom
  absolute strings and does not define VulnFuse's source identity. A .NET binary
  and post-processing step would add weight and migration work after IDs exist.
- `sarif-tools` 3.0.5 is a maintained MIT Python suite whose trim options target
  rendered result locations. It requires a Python runtime and separate workflow
  and cannot consistently relabel VulnFuse source evidence across every export.

The selected implementation uses only Node path functions already available in
the CLI and Action. Files below the working tree receive a forward-slash
relative label. An outside-root file receives only
`external-report/<basename>`; same-named outside files receive ordinals in
sorted input order. Actual paths remain available for filesystem access and
local diagnostics. This deliberately does not modify paths supplied inside a
scanner report. The compatibility cost is explicit: users whose earlier labels
were absolute receive one unavoidable ID transition, and adding or removing an
outside-root duplicate basename can renumber that narrow group.

## Design conclusions from the research

1. **Local-first is a meaningful boundary.** Scanner reports can expose package inventories, internal paths, images, hosts, and source locations. A static browser tool and offline CLI reduce the need to upload that material to another service.
2. **Provenance is more valuable than a smaller number.** Scanner disagreement reflects different discovery and matching assumptions. Collapsing rows must not erase which tool said what.
3. **Identifiers need relationships.** CVE/GHSA/OSV aliases can identify one issue; CWE describes a weakness class; upstream/downstream advisories can be related without being the same record.
4. **Asset scope is a user decision.** Incident and deployment queues usually need separate instances, while remediation planning may need one root cause across assets.
5. **A hard blocker is clearer than a negative score.** Two explicit, disjoint CVEs should not merge merely because they occur in the same package.
6. **Determinism matters in CI.** Stable outputs can be reviewed as diffs, pinned by release, and reproduced without a model or live database.
7. **A severity gate needs a baseline.** Failing on every known high-severity issue makes adoption harder and hides whether a change introduced risk. A baseline comparison can gate new clusters while still reporting updated, unchanged, and missing evidence.
8. **A review artifact should survive outside the tool.** A self-contained HTML file gives a reviewer search, filters, provenance, and baseline context without deploying VulnFuse or uploading the underlying reports.
9. **Scanner coverage is not a vote.** Exclusive and shared clusters reveal tool divergence, but correctness still depends on package identity, advisory applicability, asset context, and the retained source evidence.
10. **Suppression is evidence-bearing disposition.** It should affect active queues only under conservative, explicit semantics, while the producer's kind, status, and justification remain reviewable.
11. **Rule outcomes are evidence, not all vulnerabilities.** SARIF pass, informational, and not-applicable records should remain reviewable without entering active vulnerability gates, while malformed or contradicted outcomes fail closed.
12. **Partial scan evidence and scan completeness are separate decisions.** Retain valid findings from a failed run, but make producer-declared incompleteness visible and optionally gateable after the artifact exists.
13. **Portable path evidence should not expose machine identity.** Relative SARIF URI-base segments can improve correlation, while absolute producer roots remain private and cannot substitute for an explicit consumer checkout mapping.
14. **Equivalent standard serializations should not require a second workflow.** CycloneDX XML can reuse the JSON canonical model when the mapping is explicit and bounded, while formal schema validation and lossless conversion remain separate jobs.

## What this project intentionally does not claim

- The cited divergence study does not establish which scanner is correct for a given finding.
- A correlation cluster does not establish exploitability, reachability, remediation, or false-positive status.
- VulnFuse is not a substitute for DefectDojo or another vulnerability-management platform; it is a portable preprocessing and review layer.
- Current parser coverage is based on documented/common JSON shapes, deterministic synthetic tests, and narrow public-report smoke checks, not every historical vendor version.
- No star, adoption, or time-savings result is claimed before independent users verify it.

These boundaries are part of the product: the project should gain trust by making less up, not by presenting correlation as certainty.

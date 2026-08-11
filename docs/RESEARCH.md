# Why VulnFuse exists

VulnFuse was selected after comparing several open-source project directions in August 2026, including local file transfer, export viewers, metadata sanitizers, Windows cleanup, location-history tools, vector conversion, browser-extension auditing, DAV clients, and security-report normalization.

The selected problem had the strongest combination of repeated user pain, open standards, multiple mature input producers, and room for a standalone local-first tool rather than another hosted dashboard.

## The practical gap

Teams increasingly run more than one scanner, but the resulting rows are neither independent evidence nor safely interchangeable. Cross-tool matching requires care because tools use different identifiers, package metadata, locations, severities, and assumptions.

This is visible even in mature vulnerability-management products. DefectDojo documents that cross-tool deduplication is disabled by default because tools report the same vulnerabilities differently, warns that broad settings can create false duplicates, and requires aligned configuration across participating tools. Its global component algorithm is a Pro feature and matches exact component names and versions across products. See DefectDojo's [deduplication tuning](https://docs.defectdojo.com/triage_findings/finding_deduplication/pro__deduplication_tuning/) and [global component deduplication](https://docs.defectdojo.com/triage_findings/finding_deduplication/pro__global_component_deduplication/) documentation.

A large August 2026 preprint covering 52,895 high-exposure Docker Hub repositories reported substantial scanner divergence: 66.8% of distinct vulnerability/package groups were flagged by only one of three vulnerability scanners and 2.7% by all three. This is not proof that any one scanner was correct, and the paper is recent rather than settled consensus; it does show why provenance must survive normalization. See [Vulnerabilities, Secrets and Misconfiguration in the Highest-Exposure Docker Hub Images](https://arxiv.org/abs/2608.02669).

VulnFuse therefore does not turn disagreement into a single verdict. It retains source records and makes the correlation claim inspectable.

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

## What this project intentionally does not claim

- The cited divergence study does not establish which scanner is correct for a given finding.
- A correlation cluster does not establish exploitability, reachability, remediation, or false-positive status.
- VulnFuse is not a substitute for DefectDojo or another vulnerability-management platform; it is a portable preprocessing and review layer.
- Current parser coverage is based on documented/common JSON shapes, deterministic synthetic tests, and narrow public-report smoke checks, not every historical vendor version.
- No star, adoption, or time-savings result is claimed before independent users verify it.

These boundaries are part of the product: the project should gain trust by making less up, not by presenting correlation as certainty.

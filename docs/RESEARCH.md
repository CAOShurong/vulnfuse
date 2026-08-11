# Why VulnFuse exists

VulnFuse was selected after comparing several open-source project directions in August 2026, including local file transfer, export viewers, metadata sanitizers, Windows cleanup, location-history tools, vector conversion, browser-extension auditing, DAV clients, and security-report normalization.

The selected problem had the strongest combination of repeated user pain, open standards, multiple mature input producers, and room for a standalone local-first tool rather than another hosted dashboard.

## The practical gap

Teams increasingly run more than one scanner, but the resulting rows are neither independent evidence nor safely interchangeable. Cross-tool matching requires care because tools use different identifiers, package metadata, locations, severities, and assumptions.

This is visible even in mature vulnerability-management products. DefectDojo documents that cross-tool deduplication is disabled by default because tools report the same vulnerabilities differently, warns that broad settings can create false duplicates, and requires aligned configuration across participating tools. Its global component algorithm is a Pro feature and matches exact component names and versions across products. See DefectDojo's [deduplication tuning](https://docs.defectdojo.com/triage_findings/finding_deduplication/pro__deduplication_tuning/) and [global component deduplication](https://docs.defectdojo.com/triage_findings/finding_deduplication/pro__global_component_deduplication/) documentation.

A large August 2026 preprint covering 52,895 high-exposure Docker Hub repositories reported substantial scanner divergence: 66.8% of distinct vulnerability/package groups were flagged by only one of three vulnerability scanners and 2.7% by all three. This is not proof that any one scanner was correct, and the paper is recent rather than settled consensus; it does show why provenance must survive normalization. See [Vulnerabilities, Secrets and Misconfiguration in the Highest-Exposure Docker Hub Images](https://arxiv.org/abs/2608.02669).

VulnFuse therefore does not turn disagreement into a single verdict. It retains source records and makes the correlation claim inspectable.

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

## What this project intentionally does not claim

- The cited divergence study does not establish which scanner is correct for a given finding.
- A correlation cluster does not establish exploitability, reachability, remediation, or false-positive status.
- VulnFuse is not a substitute for DefectDojo or another vulnerability-management platform; it is a portable preprocessing and review layer.
- Current parser coverage is based on documented/common JSON shapes, deterministic synthetic tests, and narrow public-report smoke checks, not every historical vendor version.
- No star, adoption, or time-savings result is claimed before independent users verify it.

These boundaries are part of the product: the project should gain trust by making less up, not by presenting correlation as certainty.

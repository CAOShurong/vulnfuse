# Matching policy

VulnFuse treats correlation as an explainable claim: two source records belong in one cluster only when their positive evidence reaches the configured threshold and no hard blocker applies.

The default policy is deterministic. It does not call a vulnerability database, use a machine-learning model, or infer reachability.

## Evidence score

| Feature                  | Score | Condition                                                                               |
| ------------------------ | ----: | --------------------------------------------------------------------------------------- |
| Vulnerability identifier |    40 | At least one normalized non-CWE identifier is shared, such as a CVE, GHSA, or OSV alias |
| Scanner fingerprint      |    55 | The same scanner supplied the same non-empty fingerprint                                |
| Component                |    25 | Canonical PURLs match, or the normalized ecosystem/name/version key matches             |
| Asset                    |    15 | Normalized asset type and key match                                                     |
| Location                 |    15 | Normalized file path and start line match exactly                                       |
| Nearby location          |    10 | File path matches and lines are within `lineWindow`, five lines by default              |
| Rule                     |    10 | Case-insensitive rule IDs match                                                         |
| Finding kind             |     5 | Both records use the same kind                                                          |
| Title                    |  0–10 | Jaccard similarity of meaningful lowercase tokens, multiplied by `titleWeight`          |

Scores are capped at 100. The default threshold is 70. Confidence labels are:

- `exact`: the same scanner supplied a stable shared fingerprint;
- `high`: score 85 or greater;
- `medium`: score 70–84;
- `low`: score 50–69;
- `none`: score below 50.

Confidence describes the correlation evidence. It does not describe vulnerability severity or exploitability.

## Hard blockers

A blocker prevents a merge even if the numeric score reaches the threshold.

1. **Explicit advisory conflict.** Both records have one or more vulnerability identifiers, but their sets do not intersect. A matching fingerprint or package does not override two different explicit CVEs.
2. **Component conflict.** Both records name components and their normalized names differ. Version differences alone are not treated as a name conflict because scanners often resolve versions differently.
3. **Asset conflict in `instance` scope.** Both records name assets and their normalized asset keys differ.
4. **Finding-kind conflict.** Both kinds are known and materially different. `sca` and `container` are compatible because the same package vulnerability may be described from either perspective.

The canonical JSON result includes up to 1,000 highest-scoring rejected candidates that had blockers. This includes member pairs that stopped a transitive cluster merge even when the proposed edge itself had enough positive evidence. The browser workbench shows blockers related to the selected cluster.

## Scope

### `instance`

Use this default when the queue tracks deployed or scanned instances. The same CVE in two images, repositories, or hosts remains two clusters when both reports identify different assets.

### `root-cause`

Use this when remediation is organized around the underlying package or code cause. Different asset keys do not block a match, but component, advisory, and kind conflicts still apply.

## Identifier handling

VulnFuse currently recognizes common CVE, GHSA, CWE, and OSV-family forms from structured fields and relevant text. Identifiers are uppercased and deduplicated. CWE values describe weakness classes and do not act as vulnerability identities.

OSV aliases are treated as peer identities only when a shared alias is present in the input. VulnFuse does not query OSV to expand an incomplete alias set.

## Component identity

Package URLs are parsed and serialized with `packageurl-js` before comparison. When no valid PURL exists, VulnFuse uses a lowercase `ecosystem:name:version` key. A component with no PURL or name does not contribute component evidence.

This fallback is intentionally strict about the version. A policy-driven version-range relationship is planned but not silently inferred in v0.4.x.

## Candidate indexing and limits

Comparing every finding with every other finding grows quadratically. VulnFuse creates candidate pairs from shared vulnerability IDs, components, and scanner fingerprints. When a chosen threshold and title weight allow weaker context to reach the threshold, it also indexes asset, path, and rule keys. Very low thresholds fall back to complete pair comparison to preserve correctness.

One invocation is limited to 2,000,000 candidate comparisons. If the limit is reached, split reports by repository, image, application, or host. This is preferable to silently skipping candidates.

## Clustering

Candidate pairs are scored first, then considered in descending score and confidence order with stable finding IDs as the final tie-breaker. Before union-find joins two clusters, VulnFuse evaluates every member pair across those clusters with the same hard-blocker policy. If any cross-cluster pair has an identifier, component, in-scope asset, or kind blocker, the proposed union is refused and the blocking pair is retained as rejected evidence.

This is stricter than ordinary connected-components clustering. A-B and B-C matches do not force A and C into one cluster when A-C has a hard conflict. Stronger direct evidence wins before a weaker bridge, and report order does not change the resulting partition.

Cluster-safety work is limited to 1,000,000 member-pair comparisons per invocation. VulnFuse fails with a split-by-asset recommendation instead of skipping the remaining checks or returning a partially guarded result. This conservative policy can keep a legitimate relationship separate when the supplied records do not expose enough compatible identity evidence; VulnFuse does not query OSV or another live database to repair incomplete aliases.

Every accepted matched edge within a cluster remains in the result so a reviewer can inspect the actual path of evidence.

The primary record is selected deterministically by:

1. highest severity;
2. most identifiers and populated descriptive/component fields;
3. lexicographically smallest stable finding ID.

Cluster IDs hash the sorted member IDs and identifiers. They remain stable when input order changes, but can change when source evidence changes.

## Baseline comparison

VulnFuse first correlates the baseline reports and current reports independently with the same scope and policy. It then matches the resulting clusters using the same explainable evidence and blockers used within a run. Exact cluster IDs take priority; remaining candidates are sorted by match score and assigned one-to-one in a deterministic order.

Every cluster receives one state:

- `new`: no baseline cluster matched the current cluster;
- `unchanged`: a baseline cluster matched and its significant evidence is unchanged;
- `updated`: a baseline cluster matched, but severity, title, kind, identifiers, components, assets, locations, remediation, source tools, or source-record count changed;
- `absent`: a baseline cluster did not match any current cluster.

`absent` means only that the evidence is missing from the supplied current reports. It does not prove remediation; a scanner might have failed, changed scope, or stopped reporting the affected asset.

Baseline candidate indexing uses stable IDs, vulnerability identifiers, components, scanner fingerprints, and—when the threshold allows weaker evidence—asset, path, and rule context. A comparison is capped at 1,000,000 cluster pairs and 2,000,000 underlying source-record pairs, and fails visibly rather than returning a partial diff.

## Example

Two records share `CVE-2021-44228` (+40), the same Log4j PURL (+25), the same image (+15), and compatible SCA/container kinds. Their score is at least 80, so they merge at the default threshold.

If one record instead says `CVE-2022-0778`, the explicit advisory conflict blocks the merge even if both happen to mention the same package or location.

## Policy versioning

The output records `schemaVersion`, threshold, scope, line window, and title weight. The score weights are code-level policy in v0.4.x. A declarative policy-file format is planned; until then, pin the VulnFuse release in CI when stable behavior matters.

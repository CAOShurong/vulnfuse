import type {
  CanonicalFinding,
  ClusterEdge,
  CorrelationOptions,
  CorrelationResult,
  FindingCluster,
  FindingIdentifier,
  FindingKind,
  FindingAsset,
  MatchExplanation,
  ParsedReport,
  Severity,
} from "./model.js";
import { defaultCorrelationOptions, severityOrder } from "./model.js";
import { analyzeCoverage } from "./coverage.js";
import { explainMatch } from "./match.js";
import { identifierKey, isVulnerabilityIdentifier, uniqueIdentifiers } from "./identifiers.js";
import {
  assetKey,
  componentKey,
  maxSeverity,
  normalizePath,
  stableHash,
  uniqueBy,
} from "./utils.js";

const maximumPairComparisons = 2_000_000;
const maximumClusterSafetyComparisons = 1_000_000;
const maximumRejectedCandidates = 1_000;

interface IndexedMatch {
  leftIndex: number;
  rightIndex: number;
  edge: ClusterEdge;
}

class UnionFind {
  private readonly parent: number[];
  private readonly rank: number[];
  private readonly groupMembers: number[][];

  constructor(size: number) {
    this.parent = Array.from({ length: size }, (_, index) => index);
    this.rank = Array.from({ length: size }, () => 0);
    this.groupMembers = Array.from({ length: size }, (_, index) => [index]);
  }

  find(index: number): number {
    const parent = this.parent[index];
    if (parent === undefined) throw new Error(`UnionFind index ${index} is out of range.`);
    if (parent !== index) this.parent[index] = this.find(parent);
    return this.parent[index] ?? index;
  }

  union(left: number, right: number): void {
    const leftRoot = this.find(left);
    const rightRoot = this.find(right);
    if (leftRoot === rightRoot) return;
    const leftRank = this.rank[leftRoot] ?? 0;
    const rightRank = this.rank[rightRoot] ?? 0;
    let retainedRoot: number;
    let absorbedRoot: number;
    if (leftRank < rightRank) {
      this.parent[leftRoot] = rightRoot;
      retainedRoot = rightRoot;
      absorbedRoot = leftRoot;
    } else if (leftRank > rightRank) {
      this.parent[rightRoot] = leftRoot;
      retainedRoot = leftRoot;
      absorbedRoot = rightRoot;
    } else {
      this.parent[rightRoot] = leftRoot;
      this.rank[leftRoot] = leftRank + 1;
      retainedRoot = leftRoot;
      absorbedRoot = rightRoot;
    }
    this.groupMembers[retainedRoot]?.push(...(this.groupMembers[absorbedRoot] ?? []));
    this.groupMembers[absorbedRoot] = [];
  }

  members(index: number): readonly number[] {
    return this.groupMembers[this.find(index)] ?? [];
  }
}

function confidenceRank(confidence: MatchExplanation["confidence"]): number {
  return ["none", "low", "medium", "high", "exact"].indexOf(confidence);
}

function choosePrimary(findings: CanonicalFinding[]): CanonicalFinding {
  return [...findings].sort((left, right) => {
    const dispositionDelta = findingDispositionRank(left) - findingDispositionRank(right);
    if (dispositionDelta !== 0) return dispositionDelta;
    const severityDelta =
      severityOrder.indexOf(right.severity) - severityOrder.indexOf(left.severity);
    if (severityDelta !== 0) return severityDelta;
    const leftCompleteness =
      left.identifiers.length + (left.description ? 1 : 0) + (left.component ? 1 : 0);
    const rightCompleteness =
      right.identifiers.length + (right.description ? 1 : 0) + (right.component ? 1 : 0);
    if (rightCompleteness !== leftCompleteness) return rightCompleteness - leftCompleteness;
    return left.id.localeCompare(right.id);
  })[0] as CanonicalFinding;
}

function findingDispositionRank(finding: CanonicalFinding): number {
  if (finding.nonFinding) return 2;
  if (finding.suppressed) return 1;
  return 0;
}

function makeCluster(members: CanonicalFinding[], edges: ClusterEdge[]): FindingCluster {
  const findingMembers = members.filter((member) => !member.nonFinding);
  const nonFinding = findingMembers.length === 0;
  const identifiers: FindingIdentifier[] = uniqueIdentifiers(
    members.flatMap((member) => member.identifiers),
  );
  const assets: FindingAsset[] = uniqueBy(
    members.flatMap((member) => (member.asset ? [member.asset] : [])),
    (asset) => assetKey(asset) ?? `${asset.type}:${asset.name}`,
  );
  const clusterEdges = edges.filter(
    (edge) =>
      members.some((member) => member.id === edge.leftId) &&
      members.some((member) => member.id === edge.rightId),
  );
  const confidence = clusterEdges.reduce<MatchExplanation["confidence"]>(
    (highest, edge) =>
      confidenceRank(edge.explanation.confidence) > confidenceRank(highest)
        ? edge.explanation.confidence
        : highest,
    members.length === 1 ? "exact" : "none",
  );
  const identitySeed = [
    ...identifiers.map(identifierKey).sort(),
    ...members.map((member) => member.id).sort(),
  ].join("|");

  return {
    id: `vf-${stableHash(identitySeed)}`,
    primary: choosePrimary(members),
    members: [...members].sort((left, right) => left.source.tool.localeCompare(right.source.tool)),
    severity: maxSeverity(members.map((member) => member.severity)),
    suppressed: !nonFinding && findingMembers.every((member) => member.suppressed === true),
    nonFinding,
    sourceTools: [...new Set(members.map((member) => member.source.tool))].sort(),
    identifiers,
    assets,
    confidence,
    edges: clusterEdges,
  };
}

function zeroSeverityCounts(): Record<Severity, number> {
  return { unknown: 0, info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

function zeroKindCounts(): Record<FindingKind, number> {
  return { sca: 0, sast: 0, container: 0, iac: 0, secret: 0, dast: 0, license: 0, unknown: 0 };
}

export function correlateReports(
  reports: ParsedReport[],
  options: Partial<CorrelationOptions> = {},
): CorrelationResult {
  const resolved: CorrelationOptions = { ...defaultCorrelationOptions, ...options };
  const findings = reports.flatMap((report) => report.findings);
  const unionFind = new UnionFind(findings.length);
  const edges: ClusterEdge[] = [];
  const rejectedCandidates: ClusterEdge[] = [];
  const pairs = candidatePairs(findings, resolved);
  const matchedCandidates: IndexedMatch[] = [];

  for (const [leftIndex, rightIndex] of pairs) {
    const left = findings[leftIndex];
    if (!left) continue;
    const right = findings[rightIndex];
    if (!right) continue;
    const explanation = explainMatch(left, right, resolved);
    if (explanation.matched) {
      matchedCandidates.push({
        leftIndex,
        rightIndex,
        edge: { leftId: left.id, rightId: right.id, explanation },
      });
    } else if (explanation.blockers.length > 0 && explanation.score > 0) {
      rejectedCandidates.push({ leftId: left.id, rightId: right.id, explanation });
    }
  }

  matchedCandidates.sort(compareIndexedMatches);
  const blockerCache = new Map<string, MatchExplanation>();
  const safetyBudget = { comparisons: 0 };
  for (const candidate of matchedCandidates) {
    const leftRoot = unionFind.find(candidate.leftIndex);
    const rightRoot = unionFind.find(candidate.rightIndex);
    if (leftRoot !== rightRoot) {
      const blockedBy = firstClusterBlocker(
        unionFind.members(leftRoot),
        unionFind.members(rightRoot),
        findings,
        resolved,
        blockerCache,
        safetyBudget,
      );
      if (blockedBy) {
        rejectedCandidates.push(blockedBy);
        continue;
      }
      unionFind.union(leftRoot, rightRoot);
    }
    edges.push(candidate.edge);
  }

  const groups = new Map<number, CanonicalFinding[]>();
  findings.forEach((finding, index) => {
    const root = unionFind.find(index);
    const group = groups.get(root) ?? [];
    group.push(finding);
    groups.set(root, group);
  });

  const clusters = [...groups.values()]
    .map((members) => makeCluster(members, edges))
    .sort((left, right) => {
      const severityDelta =
        severityOrder.indexOf(right.severity) - severityOrder.indexOf(left.severity);
      if (severityDelta !== 0) return severityDelta;
      return right.members.length - left.members.length || left.id.localeCompare(right.id);
    });

  const bySeverity = zeroSeverityCounts();
  const activeBySeverity = zeroSeverityCounts();
  const suppressedBySeverity = zeroSeverityCounts();
  const nonFindingBySeverity = zeroSeverityCounts();
  const byKind = zeroKindCounts();
  for (const cluster of clusters) {
    bySeverity[cluster.severity] += 1;
    if (cluster.nonFinding) nonFindingBySeverity[cluster.severity] += 1;
    else if (cluster.suppressed) suppressedBySeverity[cluster.severity] += 1;
    else activeBySeverity[cluster.severity] += 1;
    byKind[cluster.primary.kind] += 1;
  }

  const coverageInputs: Array<{
    tool: string;
    findings: number;
    sourceToolFindings: Record<string, number>;
  }> = [];
  const reportSummaries = reports.map((report) => {
    const declaredTools = report.tools?.length ? report.tools : [report.tool];
    const sourceToolFindings: Record<string, number> = Object.fromEntries(
      declaredTools.map((tool) => [tool, 0]),
    );
    for (const finding of report.findings) {
      sourceToolFindings[finding.source.tool] = (sourceToolFindings[finding.source.tool] ?? 0) + 1;
    }
    const tools = Object.keys(sourceToolFindings).sort();
    const toolVersions = normalizedToolVersions(report);
    coverageInputs.push({
      tool: report.tool,
      findings: report.findings.length,
      sourceToolFindings,
    });
    return {
      name: report.sourceName,
      format: report.format,
      tool: report.tool,
      tools,
      toolVersions,
      findings: report.findings.length,
      warnings: report.warnings,
      metadata: report.metadata,
    };
  });
  const coverage = analyzeCoverage(coverageInputs, clusters);

  return {
    schemaVersion: "1.0",
    options: resolved,
    reports: reportSummaries,
    clusters,
    rejectedCandidates: uniqueBy(
      rejectedCandidates.sort(compareRejectedCandidates),
      (edge) =>
        `${edgePairKey(edge.leftId, edge.rightId)}:${edge.explanation.blockers
          .map((blocker) => `${blocker.feature}:${blocker.message}`)
          .join("|")}`,
    ).slice(0, maximumRejectedCandidates),
    summary: {
      inputReports: reports.length,
      inputFindings: findings.length,
      clusters: clusters.length,
      activeClusters: clusters.filter((cluster) => !cluster.suppressed && !cluster.nonFinding)
        .length,
      suppressedClusters: clusters.filter((cluster) => cluster.suppressed).length,
      nonFindingClusters: clusters.filter((cluster) => cluster.nonFinding).length,
      duplicatesCollapsed: findings.length - clusters.length,
      sourceTools: coverage.tools.map((tool) => tool.tool),
      bySeverity,
      activeBySeverity,
      suppressedBySeverity,
      nonFindingBySeverity,
      byKind,
      coverage,
    },
  };
}

function normalizedToolVersions(report: ParsedReport): Record<string, string[]> {
  const versions = new Map<string, Set<string>>();
  const add = (tool: string, version: string) => {
    const normalizedTool = tool.trim();
    const normalizedVersion = version.trim();
    if (!normalizedTool || !normalizedVersion) return;
    const values = versions.get(normalizedTool) ?? new Set<string>();
    values.add(normalizedVersion);
    versions.set(normalizedTool, values);
  };
  for (const [tool, values] of Object.entries(report.toolVersions ?? {})) {
    for (const version of values) add(tool, version);
  }
  for (const finding of report.findings) {
    if (finding.source.version) add(finding.source.tool, finding.source.version);
  }
  return Object.fromEntries(
    [...versions.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([tool, values]) => [tool, [...values].sort()] as const),
  );
}

function compareIndexedMatches(left: IndexedMatch, right: IndexedMatch): number {
  return (
    right.edge.explanation.score - left.edge.explanation.score ||
    confidenceRank(right.edge.explanation.confidence) -
      confidenceRank(left.edge.explanation.confidence) ||
    edgePairKey(left.edge.leftId, left.edge.rightId).localeCompare(
      edgePairKey(right.edge.leftId, right.edge.rightId),
    )
  );
}

function compareRejectedCandidates(left: ClusterEdge, right: ClusterEdge): number {
  return (
    right.explanation.score - left.explanation.score ||
    edgePairKey(left.leftId, left.rightId).localeCompare(edgePairKey(right.leftId, right.rightId))
  );
}

function edgePairKey(leftId: string, rightId: string): string {
  return [leftId, rightId].sort().join(":");
}

function firstClusterBlocker(
  leftMembers: readonly number[],
  rightMembers: readonly number[],
  findings: readonly CanonicalFinding[],
  options: CorrelationOptions,
  cache: Map<string, MatchExplanation>,
  budget: { comparisons: number },
): ClusterEdge | undefined {
  const left = [...leftMembers].sort((a, b) =>
    (findings[a]?.id ?? "").localeCompare(findings[b]?.id ?? ""),
  );
  const right = [...rightMembers].sort((a, b) =>
    (findings[a]?.id ?? "").localeCompare(findings[b]?.id ?? ""),
  );
  for (const leftIndex of left) {
    for (const rightIndex of right) {
      const leftFinding = findings[leftIndex];
      const rightFinding = findings[rightIndex];
      if (!leftFinding || !rightFinding) continue;
      const key = edgePairKey(leftFinding.id, rightFinding.id);
      let explanation = cache.get(key);
      if (explanation === undefined) {
        budget.comparisons += 1;
        if (budget.comparisons > maximumClusterSafetyComparisons) {
          throw new Error(
            `Correlation would require more than ${maximumClusterSafetyComparisons.toLocaleString()} cluster-safety comparisons. Raise the match threshold or split the reports by asset.`,
          );
        }
        const evaluated = explainMatch(leftFinding, rightFinding, options);
        if (evaluated.blockers.length > 0) {
          explanation = evaluated;
          cache.set(key, explanation);
        }
      }
      if (explanation) {
        return {
          leftId: leftFinding.id,
          rightId: rightFinding.id,
          explanation,
        };
      }
    }
  }
  return undefined;
}

function candidatePairs(
  findings: CanonicalFinding[],
  options: CorrelationOptions,
): Array<readonly [number, number]> {
  const weakEvidenceMaximum = 5 + options.titleWeight;
  if (options.threshold <= weakEvidenceMaximum) return allPairs(findings.length);

  const buckets = new Map<string, number[]>();
  const includeContext = options.threshold <= 40 + weakEvidenceMaximum;
  findings.forEach((finding, index) => {
    const keys = new Set<string>();
    for (const identifier of finding.identifiers.filter(isVulnerabilityIdentifier)) {
      keys.add(`id:${identifierKey(identifier)}`);
    }
    const component = componentKey(finding.component);
    if (component) keys.add(`component:${component}`);
    for (const fingerprint of Object.values(finding.fingerprints)) {
      if (fingerprint) keys.add(`fingerprint:${finding.source.tool.toLowerCase()}:${fingerprint}`);
    }
    if (includeContext) {
      const asset = assetKey(finding.asset);
      const path = normalizePath(finding.location?.uri ?? finding.component?.path);
      if (asset) keys.add(`asset:${asset}`);
      if (path) keys.add(`path:${path}`);
      if (finding.ruleId) keys.add(`rule:${finding.ruleId.toLowerCase()}`);
    }
    for (const key of keys) {
      const bucket = buckets.get(key) ?? [];
      bucket.push(index);
      buckets.set(key, bucket);
    }
  });

  const encoded = new Set<string>();
  for (const bucket of buckets.values()) {
    for (let left = 0; left < bucket.length; left += 1) {
      for (let right = left + 1; right < bucket.length; right += 1) {
        const leftIndex = bucket[left];
        const rightIndex = bucket[right];
        if (leftIndex === undefined || rightIndex === undefined) continue;
        encoded.add(`${Math.min(leftIndex, rightIndex)}:${Math.max(leftIndex, rightIndex)}`);
        if (encoded.size > maximumPairComparisons) {
          throw new Error(
            `Correlation would require more than ${maximumPairComparisons.toLocaleString()} candidate comparisons. Split the reports by repository, image, or application and run VulnFuse per asset.`,
          );
        }
      }
    }
  }
  return [...encoded].map(
    (value) => value.split(":").map(Number) as unknown as readonly [number, number],
  );
}

function allPairs(length: number): Array<readonly [number, number]> {
  const pairs: Array<readonly [number, number]> = [];
  for (let left = 0; left < length; left += 1) {
    for (let right = left + 1; right < length; right += 1) {
      pairs.push([left, right]);
      if (pairs.length > maximumPairComparisons) {
        throw new Error(
          `Correlation would require more than ${maximumPairComparisons.toLocaleString()} pair comparisons. Raise the match threshold or split the reports by asset.`,
        );
      }
    }
  }
  return pairs;
}

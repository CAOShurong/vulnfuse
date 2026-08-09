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
const maximumRejectedCandidates = 1_000;

class UnionFind {
  private readonly parent: number[];
  private readonly rank: number[];

  constructor(size: number) {
    this.parent = Array.from({ length: size }, (_, index) => index);
    this.rank = Array.from({ length: size }, () => 0);
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
    if (leftRank < rightRank) this.parent[leftRoot] = rightRoot;
    else if (leftRank > rightRank) this.parent[rightRoot] = leftRoot;
    else {
      this.parent[rightRoot] = leftRoot;
      this.rank[leftRoot] = leftRank + 1;
    }
  }
}

function confidenceRank(confidence: MatchExplanation["confidence"]): number {
  return ["none", "low", "medium", "high", "exact"].indexOf(confidence);
}

function choosePrimary(findings: CanonicalFinding[]): CanonicalFinding {
  return [...findings].sort((left, right) => {
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

function makeCluster(members: CanonicalFinding[], edges: ClusterEdge[]): FindingCluster {
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

  for (const [leftIndex, rightIndex] of pairs) {
    const left = findings[leftIndex];
    if (!left) continue;
    const right = findings[rightIndex];
    if (!right) continue;
    const explanation = explainMatch(left, right, resolved);
    if (explanation.matched) {
      unionFind.union(leftIndex, rightIndex);
      edges.push({ leftId: left.id, rightId: right.id, explanation });
    } else if (explanation.blockers.length > 0 && explanation.score > 0) {
      rejectedCandidates.push({ leftId: left.id, rightId: right.id, explanation });
    }
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
  const byKind = zeroKindCounts();
  for (const cluster of clusters) {
    bySeverity[cluster.severity] += 1;
    byKind[cluster.primary.kind] += 1;
  }

  return {
    schemaVersion: "1.0",
    options: resolved,
    reports: reports.map((report) => ({
      name: report.sourceName,
      format: report.format,
      tool: report.tool,
      findings: report.findings.length,
      warnings: report.warnings,
    })),
    clusters,
    rejectedCandidates: rejectedCandidates
      .sort((left, right) => right.explanation.score - left.explanation.score)
      .slice(0, maximumRejectedCandidates),
    summary: {
      inputReports: reports.length,
      inputFindings: findings.length,
      clusters: clusters.length,
      duplicatesCollapsed: findings.length - clusters.length,
      sourceTools: [...new Set(reports.map((report) => report.tool))].sort(),
      bySeverity,
      byKind,
    },
  };
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

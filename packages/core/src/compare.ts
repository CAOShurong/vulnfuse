import { identifierKey, isVulnerabilityIdentifier } from "./identifiers.js";
import { explainMatch } from "./match.js";
import {
  severityOrder,
  type BaselineDiffItem,
  type BaselineDiffResult,
  type CorrelationOptions,
  type CorrelationResult,
  type FindingCluster,
  type MatchExplanation,
  type Severity,
} from "./model.js";
import { assetKey, componentKey, normalizePath } from "./utils.js";

const maximumClusterComparisons = 1_000_000;
const maximumBaselineMemberComparisons = 2_000_000;

interface Candidate {
  baselineIndex: number;
  currentIndex: number;
  explanation: MatchExplanation;
  exactId: boolean;
}

export function compareCorrelations(
  baseline: CorrelationResult,
  current: CorrelationResult,
): BaselineDiffResult {
  if (baseline.options.scope !== current.options.scope) {
    throw new Error(
      `Baseline scope '${baseline.options.scope}' does not match current scope '${current.options.scope}'. Rebuild both with the same scope before comparing them.`,
    );
  }

  const candidates = matchCandidates(baseline.clusters, current.clusters, current.options);
  const matchedBaseline = new Set<number>();
  const matchedCurrent = new Set<number>();
  const items: BaselineDiffItem[] = [];

  for (const candidate of candidates) {
    if (
      matchedBaseline.has(candidate.baselineIndex) ||
      matchedCurrent.has(candidate.currentIndex)
    ) {
      continue;
    }
    const baselineCluster = baseline.clusters[candidate.baselineIndex];
    const cluster = current.clusters[candidate.currentIndex];
    if (!baselineCluster || !cluster) continue;
    matchedBaseline.add(candidate.baselineIndex);
    matchedCurrent.add(candidate.currentIndex);
    const changedFields = significantChanges(baselineCluster, cluster);
    items.push({
      state: changedFields.length === 0 ? "unchanged" : "updated",
      cluster,
      baselineCluster,
      explanation: candidate.explanation,
      changedFields,
    });
  }

  current.clusters.forEach((cluster, index) => {
    if (!matchedCurrent.has(index)) items.push({ state: "new", cluster, changedFields: [] });
  });
  baseline.clusters.forEach((cluster, index) => {
    if (!matchedBaseline.has(index)) items.push({ state: "absent", cluster, changedFields: [] });
  });

  items.sort(compareItems);
  const newBySeverity = zeroSeverityCounts();
  for (const item of items) {
    if (item.state === "new") newBySeverity[item.cluster.severity] += 1;
  }

  return {
    schemaVersion: "1.0",
    options: current.options,
    baselineSummary: baseline.summary,
    currentSummary: current.summary,
    items,
    summary: {
      baselineClusters: baseline.clusters.length,
      currentClusters: current.clusters.length,
      new: items.filter((item) => item.state === "new").length,
      updated: items.filter((item) => item.state === "updated").length,
      unchanged: items.filter((item) => item.state === "unchanged").length,
      absent: items.filter((item) => item.state === "absent").length,
      newBySeverity,
    },
  };
}

function matchCandidates(
  baseline: FindingCluster[],
  current: FindingCluster[],
  options: CorrelationOptions,
): Candidate[] {
  const pairs = candidatePairs(baseline, current, options);
  const candidates: Candidate[] = [];
  let memberComparisons = 0;
  for (const [baselineIndex, currentIndex] of pairs) {
    const baselineCluster = baseline[baselineIndex];
    const currentCluster = current[currentIndex];
    if (!baselineCluster || !currentCluster) continue;
    const exactId = baselineCluster.id === currentCluster.id;
    if (!exactId) {
      memberComparisons += baselineCluster.members.length * currentCluster.members.length;
      if (memberComparisons > maximumBaselineMemberComparisons) {
        throw new Error(
          `Baseline matching would require more than ${maximumBaselineMemberComparisons.toLocaleString()} source-record comparisons. Split the reports by repository, image, or application and compare each asset separately.`,
        );
      }
    }
    const explanation = exactId
      ? exactClusterExplanation(baselineCluster.id)
      : bestMemberExplanation(baselineCluster, currentCluster, options);
    if (explanation?.matched) {
      candidates.push({ baselineIndex, currentIndex, explanation, exactId });
    }
  }
  return candidates.sort((left, right) => {
    if (left.exactId !== right.exactId) return left.exactId ? -1 : 1;
    const score = right.explanation.score - left.explanation.score;
    if (score !== 0) return score;
    const baselineId = (baseline[left.baselineIndex]?.id ?? "").localeCompare(
      baseline[right.baselineIndex]?.id ?? "",
    );
    if (baselineId !== 0) return baselineId;
    return (current[left.currentIndex]?.id ?? "").localeCompare(
      current[right.currentIndex]?.id ?? "",
    );
  });
}

function candidatePairs(
  baseline: FindingCluster[],
  current: FindingCluster[],
  options: CorrelationOptions,
): Array<readonly [number, number]> {
  const weakEvidenceMaximum = 5 + options.titleWeight;
  if (options.threshold <= weakEvidenceMaximum) return allPairs(baseline.length, current.length);

  const baselineIndex = new Map<string, number[]>();
  baseline.forEach((cluster, index) => {
    for (const key of clusterKeys(cluster, options)) {
      const bucket = baselineIndex.get(key) ?? [];
      bucket.push(index);
      baselineIndex.set(key, bucket);
    }
  });

  const encoded = new Set<string>();
  current.forEach((cluster, currentIndex) => {
    for (const key of clusterKeys(cluster, options)) {
      for (const baselineIndexValue of baselineIndex.get(key) ?? []) {
        encoded.add(`${baselineIndexValue}:${currentIndex}`);
        if (encoded.size > maximumClusterComparisons) throwComparisonLimit();
      }
    }
  });
  return [...encoded].map(
    (value) => value.split(":").map(Number) as unknown as readonly [number, number],
  );
}

function allPairs(baselineLength: number, currentLength: number): Array<readonly [number, number]> {
  if (baselineLength * currentLength > maximumClusterComparisons) throwComparisonLimit();
  const pairs: Array<readonly [number, number]> = [];
  for (let baselineIndex = 0; baselineIndex < baselineLength; baselineIndex += 1) {
    for (let currentIndex = 0; currentIndex < currentLength; currentIndex += 1) {
      pairs.push([baselineIndex, currentIndex]);
    }
  }
  return pairs;
}

function throwComparisonLimit(): never {
  throw new Error(
    `Baseline comparison would require more than ${maximumClusterComparisons.toLocaleString()} cluster pairs. Split the reports by repository, image, or application and compare each asset separately.`,
  );
}

function clusterKeys(cluster: FindingCluster, options: CorrelationOptions): Set<string> {
  const keys = new Set<string>([`cluster:${cluster.id}`]);
  const includeContext = options.threshold <= 40 + 5 + options.titleWeight;
  for (const member of cluster.members) {
    for (const identifier of member.identifiers.filter(isVulnerabilityIdentifier)) {
      keys.add(`id:${identifierKey(identifier)}`);
    }
    const component = componentKey(member.component);
    if (component) keys.add(`component:${component}`);
    for (const value of Object.values(member.fingerprints)) {
      if (value) keys.add(`fingerprint:${member.source.tool.toLowerCase()}:${value}`);
    }
    if (includeContext) {
      const asset = assetKey(member.asset);
      const path = normalizePath(member.location?.uri ?? member.component?.path);
      if (asset) keys.add(`asset:${asset}`);
      if (path) keys.add(`path:${path}`);
      if (member.ruleId) keys.add(`rule:${member.ruleId.toLowerCase()}`);
    }
  }
  return keys;
}

function bestMemberExplanation(
  baseline: FindingCluster,
  current: FindingCluster,
  options: CorrelationOptions,
): MatchExplanation | undefined {
  let best: MatchExplanation | undefined;
  for (const baselineMember of baseline.members) {
    for (const currentMember of current.members) {
      const explanation = explainMatch(baselineMember, currentMember, options);
      if (
        explanation.matched &&
        (!best ||
          explanation.score > best.score ||
          (explanation.score === best.score &&
            confidenceRank(explanation.confidence) > confidenceRank(best.confidence)))
      ) {
        best = explanation;
      }
    }
  }
  return best;
}

function exactClusterExplanation(clusterId: string): MatchExplanation {
  return {
    score: 100,
    confidence: "exact",
    matched: true,
    reasons: [
      {
        feature: "fingerprint",
        score: 100,
        message: "Stable VulnFuse cluster identity matched the baseline.",
        evidence: [clusterId],
      },
    ],
    blockers: [],
  };
}

function significantChanges(baseline: FindingCluster, current: FindingCluster): string[] {
  const fields: Array<readonly [string, unknown, unknown]> = [
    ["severity", baseline.severity, current.severity],
    ["title", baseline.primary.title.trim(), current.primary.title.trim()],
    ["kind", baseline.primary.kind, current.primary.kind],
    ["identifiers", identifierSnapshot(baseline), identifierSnapshot(current)],
    ["components", componentSnapshot(baseline), componentSnapshot(current)],
    ["assets", assetSnapshot(baseline), assetSnapshot(current)],
    ["locations", locationSnapshot(baseline), locationSnapshot(current)],
    ["remediation", remediationSnapshot(baseline), remediationSnapshot(current)],
    ["source-tools", baseline.sourceTools, current.sourceTools],
    ["source-records", baseline.members.length, current.members.length],
  ];
  return fields
    .filter(([, before, after]) => JSON.stringify(before) !== JSON.stringify(after))
    .map(([name]) => name);
}

function identifierSnapshot(cluster: FindingCluster): string[] {
  return cluster.identifiers.map(identifierKey).sort();
}

function componentSnapshot(cluster: FindingCluster): string[] {
  return uniqueSorted(
    cluster.members.map((member) =>
      JSON.stringify({
        purl: member.component?.purl ?? "",
        ecosystem: member.component?.ecosystem ?? "",
        name: member.component?.name ?? "",
        version: member.component?.version ?? "",
        path: normalizePath(member.component?.path) ?? "",
        type: member.component?.type ?? "",
      }),
    ),
  );
}

function assetSnapshot(cluster: FindingCluster): string[] {
  return uniqueSorted(
    cluster.assets.map((asset) => assetKey(asset) ?? `${asset.type}:${asset.name.toLowerCase()}`),
  );
}

function locationSnapshot(cluster: FindingCluster): string[] {
  return uniqueSorted(
    cluster.members.map((member) =>
      JSON.stringify({
        uri: normalizePath(member.location?.uri) ?? "",
        startLine: member.location?.startLine ?? null,
        endLine: member.location?.endLine ?? null,
        startColumn: member.location?.startColumn ?? null,
        symbol: member.location?.symbol ?? "",
      }),
    ),
  );
}

function remediationSnapshot(cluster: FindingCluster): string[] {
  return uniqueSorted(
    cluster.members.map((member) =>
      JSON.stringify({
        fixedVersion: member.remediation?.fixedVersion ?? "",
        recommendation: member.remediation?.recommendation ?? "",
      }),
    ),
  );
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function confidenceRank(confidence: MatchExplanation["confidence"]): number {
  return ["none", "low", "medium", "high", "exact"].indexOf(confidence);
}

function compareItems(left: BaselineDiffItem, right: BaselineDiffItem): number {
  const stateOrder = ["new", "updated", "absent", "unchanged"];
  const state = stateOrder.indexOf(left.state) - stateOrder.indexOf(right.state);
  if (state !== 0) return state;
  const severity =
    severityOrder.indexOf(right.cluster.severity) - severityOrder.indexOf(left.cluster.severity);
  return severity || left.cluster.id.localeCompare(right.cluster.id);
}

function zeroSeverityCounts(): Record<Severity, number> {
  return { unknown: 0, info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

import type { CoverageSummary, FindingCluster, ToolCoverage, ToolPairCoverage } from "./model.js";

interface ReportCoverageInput {
  tool: string;
  findings: number;
}

const maximumPairwiseTools = 20;

export function analyzeCoverage(
  reports: ReportCoverageInput[],
  clusters: FindingCluster[],
): CoverageSummary {
  const toolNames = [...new Set(reports.map((report) => report.tool))].sort();
  const stats = new Map<string, ToolCoverage>(
    toolNames.map((tool) => [
      tool,
      {
        tool,
        reports: 0,
        sourceFindings: 0,
        clusters: 0,
        exclusiveClusters: 0,
        sharedClusters: 0,
      },
    ]),
  );
  for (const report of reports) {
    const tool = stats.get(report.tool);
    if (!tool) continue;
    tool.reports += 1;
    tool.sourceFindings += report.findings;
  }
  for (const cluster of clusters) {
    for (const toolName of cluster.sourceTools) {
      const tool = stats.get(toolName);
      if (!tool) continue;
      tool.clusters += 1;
      if (cluster.sourceTools.length === 1) tool.exclusiveClusters += 1;
      else tool.sharedClusters += 1;
    }
  }
  const tools = toolNames
    .map((tool) => stats.get(tool))
    .filter((tool): tool is ToolCoverage => Boolean(tool));
  const pairs: ToolPairCoverage[] = [];
  const pairwiseOmitted = toolNames.length > maximumPairwiseTools;
  if (!pairwiseOmitted) {
    const toolIndexes = new Map(toolNames.map((tool, index) => [tool, index]));
    const sharedPairCounts = new Map<string, number>();
    for (const cluster of clusters) {
      const indexes = cluster.sourceTools
        .map((tool) => toolIndexes.get(tool))
        .filter((index): index is number => index !== undefined)
        .sort((left, right) => left - right);
      for (let leftIndex = 0; leftIndex < indexes.length; leftIndex += 1) {
        for (let rightIndex = leftIndex + 1; rightIndex < indexes.length; rightIndex += 1) {
          const key = `${indexes[leftIndex]}:${indexes[rightIndex]}`;
          sharedPairCounts.set(key, (sharedPairCounts.get(key) ?? 0) + 1);
        }
      }
    }
    for (let leftIndex = 0; leftIndex < toolNames.length; leftIndex += 1) {
      const leftTool = toolNames[leftIndex];
      if (!leftTool) continue;
      for (let rightIndex = leftIndex + 1; rightIndex < toolNames.length; rightIndex += 1) {
        const rightTool = toolNames[rightIndex];
        if (!rightTool) continue;
        const sharedClusters = sharedPairCounts.get(`${leftIndex}:${rightIndex}`) ?? 0;
        const leftClusters = stats.get(leftTool)?.clusters ?? 0;
        const rightClusters = stats.get(rightTool)?.clusters ?? 0;
        const unionClusters = leftClusters + rightClusters - sharedClusters;
        pairs.push({
          leftTool,
          rightTool,
          sharedClusters,
          unionClusters,
          overlapRatio: unionClusters === 0 ? 0 : roundRatio(sharedClusters / unionClusters),
        });
      }
    }
    pairs.sort(
      (left, right) =>
        right.overlapRatio - left.overlapRatio ||
        right.sharedClusters - left.sharedClusters ||
        left.leftTool.localeCompare(right.leftTool) ||
        left.rightTool.localeCompare(right.rightTool),
    );
  }
  return {
    singleToolClusters: clusters.filter((cluster) => cluster.sourceTools.length === 1).length,
    multiToolClusters: clusters.filter((cluster) => cluster.sourceTools.length > 1).length,
    tools,
    pairs,
    pairwiseOmitted,
  };
}

function roundRatio(value: number): number {
  return Number(value.toFixed(4));
}

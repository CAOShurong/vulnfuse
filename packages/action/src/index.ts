import { resolve } from "node:path";

import * as core from "@actions/core";
import * as glob from "@actions/glob";
import {
  compareCorrelations,
  correlateReports,
  describeScanSetChange,
  exportBaselineDiff,
  exportCorrelation,
  parseReport,
  severityOrder,
  type BaselineDiffResult,
  type MatchScope,
  type OutputFormat,
  type ParsedReport,
  type Severity,
} from "@vulnfuse/core";
import { readFileLimited, writeFileAtomic } from "@vulnfuse/core/node";

const allowedFormats = new Set<OutputFormat>(["json", "sarif", "csv", "markdown", "html"]);
const allowedScopes = new Set<MatchScope>(["instance", "root-cause"]);
const allowedFailOn = new Set<Severity | "none">([
  "none",
  "info",
  "low",
  "medium",
  "high",
  "critical",
]);

export async function run(): Promise<void> {
  try {
    const patterns = core.getInput("reports", { required: true }).trim();
    const baselinePatterns = core.getInput("baseline-reports").trim();
    const output = resolve(core.getInput("output") || "vulnfuse-results.sarif");
    const format = inputChoice("format", "sarif", allowedFormats);
    const scope = inputChoice("scope", "instance", allowedScopes);
    const failOn = inputChoice("fail-on", "none", allowedFailOn);
    const failOnNew = inputChoice("fail-on-new", "none", allowedFailOn);
    const failOnScanSetChange = inputBoolean("fail-on-scan-set-change", false);
    const threshold = inputNumber("threshold", 70, 0, 100);
    const maxBytes = inputNumber("max-bytes", 100 * 1024 * 1024, 1, 1024 ** 3, true);
    if (!baselinePatterns && failOnNew !== "none") {
      throw new Error(
        "fail-on-new requires baseline-reports so existing findings are not treated as new.",
      );
    }
    if (!baselinePatterns && failOnScanSetChange) {
      throw new Error("fail-on-scan-set-change requires baseline-reports.");
    }

    const reports = await readMatchedReports(patterns, "current", maxBytes, output);
    const result = correlateReports(reports, { threshold, scope });
    let baselineDiff: BaselineDiffResult | undefined;
    if (baselinePatterns) {
      const baselineReports = await readMatchedReports(
        baselinePatterns,
        "baseline",
        maxBytes,
        output,
        1_000 - reports.length,
      );
      const baseline = correlateReports(baselineReports, { threshold, scope });
      baselineDiff = compareCorrelations(baseline, result);
    }
    await writeFileAtomic(
      output,
      baselineDiff ? exportBaselineDiff(baselineDiff, format) : exportCorrelation(result, format),
    );

    core.setOutput("findings", result.summary.inputFindings);
    core.setOutput("clusters", result.summary.clusters);
    core.setOutput("active", result.summary.activeClusters);
    core.setOutput("suppressed", result.summary.suppressedClusters);
    core.setOutput("non-finding", result.summary.nonFindingClusters);
    core.setOutput("duplicates-collapsed", result.summary.duplicatesCollapsed);
    core.setOutput("single-tool", result.summary.coverage.singleToolClusters);
    core.setOutput("multi-tool", result.summary.coverage.multiToolClusters);
    core.setOutput("new", baselineDiff?.summary.new ?? 0);
    core.setOutput("updated", baselineDiff?.summary.updated ?? 0);
    core.setOutput("absent", baselineDiff?.summary.absent ?? 0);
    core.setOutput("unchanged", baselineDiff?.summary.unchanged ?? 0);
    core.setOutput("scan-set-changed", baselineDiff?.scanSetChange.detected ?? false);
    core.setOutput("report", output);
    await writeSummary(result, output, baselineDiff);
    core.info(
      `${result.summary.inputFindings} source records became ${result.summary.clusters} clusters (${result.summary.activeClusters} active, ${result.summary.suppressedClusters} suppressed, and ${result.summary.nonFindingClusters} non-finding); ${result.summary.duplicatesCollapsed} duplicates collapsed.`,
    );
    core.info(
      `Coverage: ${result.summary.coverage.singleToolClusters} one-tool clusters and ${result.summary.coverage.multiToolClusters} multi-tool clusters.`,
    );
    if (baselineDiff) {
      core.info(
        `Baseline comparison: ${baselineDiff.summary.new} new, ${baselineDiff.summary.updated} updated, ${baselineDiff.summary.absent} absent, and ${baselineDiff.summary.unchanged} unchanged.`,
      );
      if (baselineDiff.scanSetChange.detected) {
        core.warning(describeScanSetChange(baselineDiff.scanSetChange));
      }
    }

    if (failOn !== "none" && hasSeverityAtLeast(result.summary.activeBySeverity, failOn)) {
      core.setFailed(
        `At least one active vulnerability cluster met the '${failOn}' severity threshold. The report was still written to ${output}.`,
      );
    }
    if (
      baselineDiff &&
      failOnNew !== "none" &&
      hasSeverityAtLeast(baselineDiff.summary.newActiveBySeverity, failOnNew)
    ) {
      core.setFailed(
        `At least one new active vulnerability cluster met the '${failOnNew}' severity threshold. The baseline comparison was still written to ${output}.`,
      );
    }
    if (baselineDiff?.scanSetChange.detected && failOnScanSetChange) {
      core.setFailed(
        `The scanner tools or per-tool report counts changed from the baseline. The comparison was still written to ${output}.`,
      );
    }
  } catch (error) {
    core.setFailed(error instanceof Error ? error.message : String(error));
  }
}

async function readMatchedReports(
  patterns: string,
  label: string,
  maxBytes: number,
  output: string,
  maximumReports = 1_000,
): Promise<ParsedReport[]> {
  const matcher = await glob.create(patterns, {
    followSymbolicLinks: false,
    implicitDescendants: false,
    matchDirectories: false,
  });
  const files = [...new Set(await matcher.glob())].sort();
  if (files.length === 0) throw new Error(`The ${label} report patterns did not match any files.`);
  if (files.length > maximumReports) {
    throw new Error(
      `Matched ${files.length} ${label} reports; at most 1,000 current and baseline reports can be processed together.`,
    );
  }
  if (files.some((file) => resolve(file).toLowerCase() === output.toLowerCase())) {
    throw new Error("The output path cannot overwrite an input report.");
  }

  core.info(`VulnFuse is reading ${files.length} ${label} report${files.length === 1 ? "" : "s"}.`);
  const reports: ParsedReport[] = [];
  for (const file of files) {
    const content = await readFileLimited(file, maxBytes);
    const report = parseReport({ name: file, content }, { maxBytes });
    core.info(`${report.tool}: ${report.findings.length} findings from ${file}`);
    for (const warning of report.warnings) {
      const path = warning.path ? ` at ${warning.path}` : "";
      core.warning(`${file}: ${warning.code}: ${warning.message}${path}`);
    }
    reports.push(report);
  }
  return reports;
}

async function writeSummary(
  result: ReturnType<typeof correlateReports>,
  output: string,
  baselineDiff?: BaselineDiffResult,
): Promise<void> {
  const table = [
    [
      { data: "Severity", header: true },
      { data: "Active", header: true },
      { data: "Suppressed", header: true },
      { data: "Non-finding", header: true },
      { data: "Total", header: true },
    ],
    ...(["critical", "high", "medium", "low", "info", "unknown"] as Severity[]).map((severity) => [
      severity,
      String(result.summary.activeBySeverity[severity]),
      String(result.summary.suppressedBySeverity[severity]),
      String(result.summary.nonFindingBySeverity[severity]),
      String(result.summary.bySeverity[severity]),
    ]),
  ];
  const coverageTable = [
    [
      { data: "Tool", header: true },
      { data: "Findings", header: true },
      { data: "Clusters", header: true },
      { data: "Only tool", header: true },
      { data: "Shared", header: true },
    ],
    ...result.summary.coverage.tools.map((tool) => [
      escapeSummary(tool.tool),
      String(tool.sourceFindings),
      String(tool.clusters),
      String(tool.exclusiveClusters),
      String(tool.sharedClusters),
    ]),
  ];
  const pairwiseCoverage = result.summary.coverage.pairwiseOmitted
    ? "Pairwise rows are omitted when more than 20 tools are present."
    : result.summary.coverage.pairs
        .map(
          (pair) =>
            `- ${escapeSummary(pair.leftTool)} / ${escapeSummary(pair.rightTool)}: ${pair.sharedClusters} shared of ${pair.unionClusters} union clusters (${(pair.overlapRatio * 100).toFixed(1)}% Jaccard)`,
        )
        .join("\n") || "Add a second scanner to measure overlap.";
  await core.summary
    .addHeading("VulnFuse correlation", 2)
    .addRaw(
      `${result.summary.inputFindings} source records became **${result.summary.clusters} clusters** (**${result.summary.activeClusters} active**, **${result.summary.suppressedClusters} suppressed**, **${result.summary.nonFindingClusters} non-finding**); **${result.summary.duplicatesCollapsed} duplicate records** were collapsed.`,
      true,
    )
    .addTable(table)
    .addHeading("Scanner coverage", 3)
    .addRaw(
      `**${result.summary.coverage.singleToolClusters} one-tool clusters** and **${result.summary.coverage.multiToolClusters} multi-tool clusters**. Agreement is evidence coverage, not a correctness vote.`,
      true,
    )
    .addTable(coverageTable)
    .addDetails("Pairwise scanner overlap", pairwiseCoverage)
    .addRaw(
      baselineDiff
        ? `Baseline: **${baselineDiff.summary.new} new**, **${baselineDiff.summary.updated} updated**, **${baselineDiff.summary.absent} absent**, and ${baselineDiff.summary.unchanged} unchanged.`
        : "",
      Boolean(baselineDiff),
    )
    .addRaw(
      baselineDiff?.scanSetChange.detected
        ? `**Scan set changed.** ${escapeSummary(describeScanSetChange(baselineDiff.scanSetChange).replace(/^Scan set changed:\s*/, ""))}`
        : "",
      Boolean(baselineDiff?.scanSetChange.detected),
    )
    .addDetails(
      baselineDiff ? "Highest-severity new clusters" : "Highest-severity clusters",
      (baselineDiff
        ? baselineDiff.items.filter((item) => item.state === "new").map((item) => item.cluster)
        : result.clusters
      )
        .slice(0, 20)
        .map(
          (cluster) =>
            `- **${cluster.severity.toUpperCase()}** ${escapeSummary(cluster.primary.title)} (${cluster.nonFinding ? "non-finding evidence" : cluster.suppressed ? "effectively suppressed" : "active"}) — ${cluster.members.length} record${cluster.members.length === 1 ? "" : "s"} from ${cluster.sourceTools.join(", ")}`,
        )
        .join("\n") || "No findings.",
    )
    .addRaw(`Report: \`${output}\``, true)
    .write();
}

function inputChoice<T extends string>(name: string, fallback: T, choices: Set<T>): T {
  const value = (core.getInput(name) || fallback).trim() as T;
  if (!choices.has(value)) throw new Error(`${name} must be one of: ${[...choices].join(", ")}.`);
  return value;
}

function inputNumber(
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
  integer = false,
): number {
  const value = Number(core.getInput(name) || fallback);
  if (
    !Number.isFinite(value) ||
    value < minimum ||
    value > maximum ||
    (integer && !Number.isInteger(value))
  ) {
    throw new Error(
      `${name} must be ${integer ? "an integer" : "a number"} from ${minimum} to ${maximum}.`,
    );
  }
  return value;
}

function inputBoolean(name: string, fallback: boolean): boolean {
  const value = core.getInput(name).trim().toLowerCase();
  if (!value) return fallback;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error(`${name} must be true or false.`);
}

function hasSeverityAtLeast(counts: Record<Severity, number>, threshold: Severity): boolean {
  const minimum = severityOrder.indexOf(threshold);
  return severityOrder.some((severity, index) => index >= minimum && counts[severity] > 0);
}

function escapeSummary(value: string): string {
  return value.replace(/[<>]/g, "");
}

void run();

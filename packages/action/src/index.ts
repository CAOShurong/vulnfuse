import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import * as core from "@actions/core";
import * as glob from "@actions/glob";
import {
  correlateReports,
  exportCorrelation,
  parseReport,
  severityOrder,
  type MatchScope,
  type OutputFormat,
  type Severity,
} from "@vulnfuse/core";

const allowedFormats = new Set<OutputFormat>(["json", "sarif", "csv", "markdown"]);
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
    const output = resolve(core.getInput("output") || "vulnfuse-results.sarif");
    const format = inputChoice("format", "sarif", allowedFormats);
    const scope = inputChoice("scope", "instance", allowedScopes);
    const failOn = inputChoice("fail-on", "none", allowedFailOn);
    const threshold = inputNumber("threshold", 70, 0, 100);
    const maxBytes = inputNumber("max-bytes", 100 * 1024 * 1024, 1, 1024 ** 3, true);

    const matcher = await glob.create(patterns, {
      followSymbolicLinks: false,
      implicitDescendants: false,
      matchDirectories: false,
    });
    const files = [...new Set(await matcher.glob())].sort();
    if (files.length === 0) throw new Error("The reports patterns did not match any files.");
    if (files.length > 1_000)
      throw new Error(`Matched ${files.length} reports; the safety limit is 1,000.`);
    if (files.some((file) => resolve(file).toLowerCase() === output.toLowerCase())) {
      throw new Error("The output path cannot overwrite an input report.");
    }

    core.info(`VulnFuse is reading ${files.length} report${files.length === 1 ? "" : "s"}.`);
    const reports = [];
    for (const file of files) {
      const buffer = await readFile(file);
      if (buffer.byteLength > maxBytes) {
        throw new Error(
          `${file} is ${buffer.byteLength.toLocaleString()} bytes; the configured limit is ${maxBytes.toLocaleString()} bytes.`,
        );
      }
      const report = parseReport({ name: file, content: buffer.toString("utf8") }, { maxBytes });
      core.info(`${report.tool}: ${report.findings.length} findings from ${file}`);
      reports.push(report);
    }

    const result = correlateReports(reports, { threshold, scope });
    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, exportCorrelation(result, format), "utf8");

    core.setOutput("findings", result.summary.inputFindings);
    core.setOutput("clusters", result.summary.clusters);
    core.setOutput("duplicates-collapsed", result.summary.duplicatesCollapsed);
    core.setOutput("report", output);
    await writeSummary(result, output);
    core.info(
      `${result.summary.inputFindings} source findings became ${result.summary.clusters} clusters; ${result.summary.duplicatesCollapsed} duplicates collapsed.`,
    );

    if (failOn !== "none" && hasSeverityAtLeast(result.summary.bySeverity, failOn)) {
      core.setFailed(
        `At least one vulnerability cluster met the '${failOn}' severity threshold. The report was still written to ${output}.`,
      );
    }
  } catch (error) {
    core.setFailed(error instanceof Error ? error.message : String(error));
  }
}

async function writeSummary(
  result: ReturnType<typeof correlateReports>,
  output: string,
): Promise<void> {
  const table = [
    [
      { data: "Severity", header: true },
      { data: "Clusters", header: true },
    ],
    ...(["critical", "high", "medium", "low", "info", "unknown"] as Severity[]).map((severity) => [
      severity,
      String(result.summary.bySeverity[severity]),
    ]),
  ];
  await core.summary
    .addHeading("VulnFuse correlation", 2)
    .addRaw(
      `${result.summary.inputFindings} source findings became **${result.summary.clusters} clusters**; **${result.summary.duplicatesCollapsed} duplicate records** were collapsed.`,
      true,
    )
    .addTable(table)
    .addDetails(
      "Highest-severity clusters",
      result.clusters
        .slice(0, 20)
        .map(
          (cluster) =>
            `- **${cluster.severity.toUpperCase()}** ${escapeSummary(cluster.primary.title)} — ${cluster.members.length} record${cluster.members.length === 1 ? "" : "s"} from ${cluster.sourceTools.join(", ")}`,
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

function hasSeverityAtLeast(counts: Record<Severity, number>, threshold: Severity): boolean {
  const minimum = severityOrder.indexOf(threshold);
  return severityOrder.some((severity, index) => index >= minimum && counts[severity] > 0);
}

function escapeSummary(value: string): string {
  return value.replace(/[<>]/g, "");
}

void run();

import { stat } from "node:fs/promises";
import { resolve } from "node:path";

import {
  compareCorrelations,
  countIncompleteReports,
  correlateReports,
  describeScanSetChange,
  detectFormat,
  exportBaselineDiff,
  exportCorrelation,
  parseReport,
  severityOrder,
  type MatchScope,
  type OutputFormat,
  type ParsedReport,
  type ReportInput,
  type Severity,
} from "@vulnfuse/core";
import { Command, InvalidArgumentError, Option } from "commander";
import { glob, isDynamicPattern } from "tinyglobby";
import { readFileLimited, writeFileAtomic } from "@vulnfuse/core/node";

const version = "0.4.17";
const maxReports = 1_000;

interface MergeOptions {
  format: OutputFormat;
  output?: string;
  threshold: number;
  scope: MatchScope;
  lineWindow: number;
  titleWeight: number;
  maxBytes: number;
  failOn: Severity | "none";
  failOnIncomplete?: boolean;
}

interface DiffOptions extends Omit<MergeOptions, "failOn"> {
  baseline: string[];
  failOnNew: Severity | "none";
  failOnScanSetChange?: boolean;
}

export function createProgram(): Command {
  const program = new Command()
    .name("vulnfuse")
    .description(
      "Correlate duplicate vulnerability findings across scanners without hiding source evidence.",
    )
    .version(version)
    .option("--debug", "Show runtime stack traces; output may include local paths")
    .showHelpAfterError();

  program
    .command("merge")
    .description("Parse and correlate two or more scanner reports.")
    .argument("<reports...>", "Report paths, glob patterns, or '-' for standard input")
    .addOption(
      new Option("-f, --format <format>", "Output format")
        .choices(["json", "sarif", "csv", "markdown", "html"])
        .default("json"),
    )
    .option("-o, --output <path>", "Write output atomically to a file instead of stdout")
    .option("--threshold <0-100>", "Minimum match score", boundedNumber(0, 100), 70)
    .addOption(
      new Option("--scope <scope>", "Correlation scope")
        .choices(["instance", "root-cause"])
        .default("instance"),
    )
    .option(
      "--line-window <lines>",
      "Maximum line distance for a location match",
      boundedInteger(0, 10_000),
      5,
    )
    .option("--title-weight <0-25>", "Maximum title-similarity score", boundedNumber(0, 25), 10)
    .option(
      "--max-bytes <bytes>",
      "Maximum bytes per report",
      boundedInteger(1, 1024 ** 3),
      100 * 1024 * 1024,
    )
    .addOption(
      new Option("--fail-on <severity>", "Exit 1 when an active cluster meets this severity")
        .choices(["none", "info", "low", "medium", "high", "critical"])
        .default("none"),
    )
    .option(
      "--fail-on-incomplete",
      "Exit 1 after writing when SARIF metadata says an input run may be incomplete",
    )
    .action(async (reportPaths: string[], options: MergeOptions) => {
      reportPaths = await expandReportPaths(reportPaths);
      assertReportArguments(reportPaths);
      assertOutputIsNotInput(options.output, reportPaths);
      const inputs = await readInputs(reportPaths, options.maxBytes);
      const reports = inputs.map((input) => parseReport(input, { maxBytes: options.maxBytes }));
      printReportWarnings(reports);
      const result = correlateReports(reports, {
        threshold: options.threshold,
        scope: options.scope,
        lineWindow: options.lineWindow,
        titleWeight: options.titleWeight,
      });
      const output = exportCorrelation(result, options.format);
      if (options.output) await writeFileAtomic(options.output, output);
      else process.stdout.write(output);
      if (
        options.failOn !== "none" &&
        hasSeverityAtLeast(result.summary.activeBySeverity, options.failOn)
      ) {
        process.exitCode = 1;
      }
      applyIncompleteGate(reports, options.failOnIncomplete, options.output);
    });

  program
    .command("diff")
    .description("Compare current reports with one or more baseline reports.")
    .argument("<reports...>", "Current report paths, glob patterns, or '-' for standard input")
    .option(
      "-b, --baseline <path>",
      "Baseline report path or glob; repeat for multiple patterns",
      collectValue,
      [],
    )
    .addOption(
      new Option("-f, --format <format>", "Output format")
        .choices(["json", "sarif", "csv", "markdown", "html"])
        .default("json"),
    )
    .option("-o, --output <path>", "Write output atomically to a file instead of stdout")
    .option("--threshold <0-100>", "Minimum match score", boundedNumber(0, 100), 70)
    .addOption(
      new Option("--scope <scope>", "Correlation scope")
        .choices(["instance", "root-cause"])
        .default("instance"),
    )
    .option(
      "--line-window <lines>",
      "Maximum line distance for a location match",
      boundedInteger(0, 10_000),
      5,
    )
    .option("--title-weight <0-25>", "Maximum title-similarity score", boundedNumber(0, 25), 10)
    .option(
      "--max-bytes <bytes>",
      "Maximum bytes per report",
      boundedInteger(1, 1024 ** 3),
      100 * 1024 * 1024,
    )
    .addOption(
      new Option("--fail-on-new <severity>", "Exit 1 when a new active cluster meets this severity")
        .choices(["none", "info", "low", "medium", "high", "critical"])
        .default("none"),
    )
    .option(
      "--fail-on-scan-set-change",
      "Exit 1 after writing when scanner identity or available SARIF category evidence changed",
    )
    .option(
      "--fail-on-incomplete",
      "Exit 1 after writing when current or baseline SARIF may be incomplete",
    )
    .action(async (reportPaths: string[], options: DiffOptions) => {
      reportPaths = await expandReportPaths(reportPaths, "Current report pattern");
      options.baseline = await expandReportPaths(options.baseline, "Baseline report pattern");
      assertReportArguments(reportPaths);
      assertReportArguments(options.baseline, "baseline report");
      if (options.baseline.length + reportPaths.length > maxReports) {
        throw new Error(
          `At most ${maxReports} current and baseline reports can be processed in one invocation.`,
        );
      }
      if ([...options.baseline, ...reportPaths].filter((path) => path === "-").length > 1) {
        throw new Error(
          "Standard input ('-') can only be used once across baseline and current reports.",
        );
      }
      assertOutputIsNotInput(options.output, [...options.baseline, ...reportPaths]);
      const baselineInputs = await readInputs(options.baseline, options.maxBytes);
      const currentInputs = await readInputs(reportPaths, options.maxBytes);
      const correlationOptions = {
        threshold: options.threshold,
        scope: options.scope,
        lineWindow: options.lineWindow,
        titleWeight: options.titleWeight,
      };
      const baselineReports = baselineInputs.map((input) =>
        parseReport(input, { maxBytes: options.maxBytes }),
      );
      const currentReports = currentInputs.map((input) =>
        parseReport(input, { maxBytes: options.maxBytes }),
      );
      printReportWarnings(baselineReports);
      printReportWarnings(currentReports);
      const baseline = correlateReports(baselineReports, correlationOptions);
      const current = correlateReports(currentReports, correlationOptions);
      const result = compareCorrelations(baseline, current);
      const output = exportBaselineDiff(result, options.format);
      if (options.output) await writeFileAtomic(options.output, output);
      else process.stdout.write(output);
      if (result.scanSetChange.detected) {
        process.stderr.write(`vulnfuse: warning: ${describeScanSetChange(result.scanSetChange)}\n`);
      }
      if (
        options.failOnNew !== "none" &&
        hasSeverityAtLeast(result.summary.newActiveBySeverity, options.failOnNew)
      ) {
        process.exitCode = 1;
      }
      if (options.failOnScanSetChange && result.scanSetChange.detected) process.exitCode = 1;
      applyIncompleteGate(
        [...baselineReports, ...currentReports],
        options.failOnIncomplete,
        options.output,
      );
    });

  program
    .command("inspect")
    .description("Detect formats and summarize reports without correlating them.")
    .argument("<reports...>", "Report paths, glob patterns, or '-' for standard input")
    .option(
      "--max-bytes <bytes>",
      "Maximum bytes per report",
      boundedInteger(1, 1024 ** 3),
      100 * 1024 * 1024,
    )
    .option("--json", "Emit machine-readable JSON")
    .option(
      "--fail-on-incomplete",
      "Exit 1 when SARIF metadata says an inspected run may be incomplete",
    )
    .action(
      async (
        reportPaths: string[],
        options: { maxBytes: number; json?: boolean; failOnIncomplete?: boolean },
      ) => {
        reportPaths = await expandReportPaths(reportPaths);
        assertReportArguments(reportPaths);
        const inputs = await readInputs(reportPaths, options.maxBytes);
        const reports = inputs.map((input) => parseReport(input, { maxBytes: options.maxBytes }));
        printReportWarnings(reports);
        if (options.json)
          process.stdout.write(`${JSON.stringify(reports.map(reportSummary), null, 2)}\n`);
        else process.stdout.write(inspectTable(reports));
        applyIncompleteGate(reports, options.failOnIncomplete);
      },
    );

  program
    .command("detect")
    .description("Print only the detected format for one report.")
    .argument("<report>", "Report path, glob matching one file, or '-' for standard input")
    .action(async (reportPath: string) => {
      const reportPaths = await expandReportPaths([reportPath]);
      if (reportPaths.length !== 1) {
        throw new Error(
          `detect requires exactly one report; the pattern matched ${reportPaths.length}.`,
        );
      }
      const [input] = await readInputs(reportPaths, 100 * 1024 * 1024);
      if (!input) throw new Error("No report was supplied.");
      process.stdout.write(`${detectFormat(input.content, input.name)}\n`);
    });

  return program;
}

async function expandReportPaths(paths: string[], label = "Report pattern"): Promise<string[]> {
  const expanded: string[] = [];
  const seen = new Set<string>();
  const add = (path: string) => {
    const key = path === "-" ? path : deduplicationPath(path);
    if (seen.has(key)) return;
    seen.add(key);
    expanded.push(path);
  };

  for (const path of paths) {
    if (path === "-" || (await pathExists(path))) {
      add(path);
      continue;
    }
    const pattern = portablePattern(path);
    if (!isDynamicPattern(pattern)) {
      add(path);
      continue;
    }
    const matches = await glob(pattern, {
      absolute: true,
      caseSensitiveMatch: process.platform !== "win32",
      dot: true,
      expandDirectories: false,
      followSymbolicLinks: false,
      onlyFiles: true,
    });
    if (matches.length === 0) throw new Error(`${label} '${path}' did not match any files.`);
    for (const match of matches.sort()) add(match);
  }
  return expanded;
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch (error) {
    if (
      error instanceof Error &&
      "code" in error &&
      (error.code === "ENOENT" || error.code === "ENOTDIR")
    ) {
      return false;
    }
    throw error;
  }
}

function portablePattern(pattern: string): string {
  return process.platform === "win32" ? pattern.replaceAll("\\", "/") : pattern;
}

function deduplicationPath(path: string): string {
  const absolute = resolve(path);
  return process.platform === "win32" ? absolute.toLowerCase() : absolute;
}

async function readInputs(paths: string[], maxBytes: number): Promise<ReportInput[]> {
  const stdinCount = paths.filter((value) => value === "-").length;
  if (stdinCount > 1) throw new Error("Standard input ('-') can only be used once.");
  let stdin: string | undefined;
  const inputs: ReportInput[] = [];
  for (const path of paths) {
    if (path === "-") {
      stdin ??= await readStdin(maxBytes);
      inputs.push({ name: "stdin", content: stdin });
    } else {
      const content = await readFileLimited(path, maxBytes);
      inputs.push({ name: path, content });
    }
  }
  return inputs;
}

async function readStdin(maxBytes: number): Promise<string> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += buffer.byteLength;
    if (length > maxBytes)
      throw new Error(
        `Standard input exceeded the configured ${maxBytes.toLocaleString()} byte limit.`,
      );
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function reportSummary(report: ParsedReport) {
  const nonFinding = report.findings.filter((finding) => finding.nonFinding).length;
  const suppressed = report.findings.filter(
    (finding) => !finding.nonFinding && finding.suppressed,
  ).length;
  return {
    name: report.sourceName,
    format: report.format,
    tool: report.tool,
    findings: report.findings.length,
    active: report.findings.length - nonFinding - suppressed,
    suppressed,
    nonFinding,
    warnings: report.warnings,
  };
}

function printReportWarnings(reports: ParsedReport[]): void {
  for (const report of reports) {
    for (const warning of report.warnings) {
      const path = warning.path ? ` at ${warning.path}` : "";
      process.stderr.write(
        `vulnfuse: warning: ${report.sourceName}: ${warning.code}: ${warning.message}${path}\n`,
      );
    }
  }
}

function applyIncompleteGate(
  reports: ParsedReport[],
  enabled: boolean | undefined,
  output?: string,
): void {
  if (!enabled) return;
  const count = countIncompleteReports(reports);
  if (count === 0) return;
  const outputNote = output ? ` The requested output was still written to ${output}.` : "";
  process.stderr.write(
    `vulnfuse: incomplete: ${count} input report${count === 1 ? "" : "s"} contained SARIF run-completeness warnings.${outputNote}\n`,
  );
  process.exitCode = 1;
}

function inspectTable(reports: ParsedReport[]): string {
  const lines = [
    "FORMAT       RECORDS  ACTIVE  SUPPRESSED  NON-FINDING  TOOL                 REPORT",
  ];
  for (const report of reports) {
    const summary = reportSummary(report);
    lines.push(
      `${report.format.padEnd(12)} ${String(summary.findings).padStart(7)}  ${String(summary.active).padStart(6)}  ${String(summary.suppressed).padStart(10)}  ${String(summary.nonFinding).padStart(11)}  ${report.tool.slice(0, 20).padEnd(20)} ${report.sourceName}`,
    );
    for (const warning of report.warnings)
      lines.push(`  warning: ${warning.code}: ${warning.message}`);
  }
  return `${lines.join("\n")}\n`;
}

function assertReportArguments(paths: string[], label = "report"): void {
  if (paths.length === 0) throw new Error(`Supply at least one ${label}.`);
  if (paths.length > maxReports)
    throw new Error(`At most ${maxReports} reports can be processed in one invocation.`);
}

function collectValue(value: string, previous: string[]): string[] {
  return [...previous, value];
}

function assertOutputIsNotInput(output: string | undefined, paths: string[]): void {
  if (!output) return;
  const destination = resolve(output).toLowerCase();
  if (paths.some((path) => path !== "-" && resolve(path).toLowerCase() === destination)) {
    throw new Error("The output path cannot overwrite an input report.");
  }
}

function hasSeverityAtLeast(counts: Record<Severity, number>, threshold: Severity): boolean {
  const minimum = severityOrder.indexOf(threshold);
  return severityOrder.some((severity, index) => index >= minimum && counts[severity] > 0);
}

function boundedNumber(minimum: number, maximum: number) {
  return (value: string): number => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed < minimum || parsed > maximum) {
      throw new InvalidArgumentError(`Expected a number from ${minimum} to ${maximum}.`);
    }
    return parsed;
  };
}

function boundedInteger(minimum: number, maximum: number) {
  return (value: string): number => {
    const parsed = Number(value);
    if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
      throw new InvalidArgumentError(`Expected an integer from ${minimum} to ${maximum}.`);
    }
    return parsed;
  };
}

const program = createProgram();
try {
  await program.parseAsync(process.argv);
} catch (error) {
  process.stderr.write(`${formatRuntimeError(error, Boolean(program.opts().debug))}\n`);
  process.exitCode = 1;
}

function formatRuntimeError(error: unknown, debug: boolean): string {
  if (error instanceof Error) {
    const detail = debug && error.stack ? error.stack : error.message;
    return `vulnfuse: ${detail || error.name}`;
  }
  return `vulnfuse: ${String(error) || "Unknown runtime error"}`;
}

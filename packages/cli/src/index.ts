import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import {
  compareCorrelations,
  correlateReports,
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

const version = "0.4.3";
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
}

interface DiffOptions extends Omit<MergeOptions, "failOn"> {
  baseline: string[];
  failOnNew: Severity | "none";
}

export function createProgram(): Command {
  const program = new Command()
    .name("vulnfuse")
    .description(
      "Correlate duplicate vulnerability findings across scanners without hiding source evidence.",
    )
    .version(version)
    .showHelpAfterError();

  program
    .command("merge")
    .description("Parse and correlate two or more scanner reports.")
    .argument("<reports...>", "Report paths, or '-' for standard input")
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
      new Option("--fail-on <severity>", "Exit 1 when a cluster meets this severity")
        .choices(["none", "info", "low", "medium", "high", "critical"])
        .default("none"),
    )
    .action(async (reportPaths: string[], options: MergeOptions) => {
      assertReportArguments(reportPaths);
      assertOutputIsNotInput(options.output, reportPaths);
      const inputs = await readInputs(reportPaths, options.maxBytes);
      const reports = inputs.map((input) => parseReport(input, { maxBytes: options.maxBytes }));
      const result = correlateReports(reports, {
        threshold: options.threshold,
        scope: options.scope,
        lineWindow: options.lineWindow,
        titleWeight: options.titleWeight,
      });
      const output = exportCorrelation(result, options.format);
      if (options.output) await atomicWrite(options.output, output);
      else process.stdout.write(output);
      if (
        options.failOn !== "none" &&
        hasSeverityAtLeast(result.summary.bySeverity, options.failOn)
      ) {
        process.exitCode = 1;
      }
    });

  program
    .command("diff")
    .description("Compare current reports with one or more baseline reports.")
    .argument("<reports...>", "Current report paths, or '-' for standard input")
    .option(
      "-b, --baseline <path>",
      "Baseline report path; repeat for multiple scanner reports",
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
      new Option("--fail-on-new <severity>", "Exit 1 when a new cluster meets this severity")
        .choices(["none", "info", "low", "medium", "high", "critical"])
        .default("none"),
    )
    .action(async (reportPaths: string[], options: DiffOptions) => {
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
      const baseline = correlateReports(
        baselineInputs.map((input) => parseReport(input, { maxBytes: options.maxBytes })),
        correlationOptions,
      );
      const current = correlateReports(
        currentInputs.map((input) => parseReport(input, { maxBytes: options.maxBytes })),
        correlationOptions,
      );
      const result = compareCorrelations(baseline, current);
      const output = exportBaselineDiff(result, options.format);
      if (options.output) await atomicWrite(options.output, output);
      else process.stdout.write(output);
      if (
        options.failOnNew !== "none" &&
        hasSeverityAtLeast(result.summary.newBySeverity, options.failOnNew)
      ) {
        process.exitCode = 1;
      }
    });

  program
    .command("inspect")
    .description("Detect formats and summarize reports without correlating them.")
    .argument("<reports...>", "Report paths, or '-' for standard input")
    .option(
      "--max-bytes <bytes>",
      "Maximum bytes per report",
      boundedInteger(1, 1024 ** 3),
      100 * 1024 * 1024,
    )
    .option("--json", "Emit machine-readable JSON")
    .action(async (reportPaths: string[], options: { maxBytes: number; json?: boolean }) => {
      assertReportArguments(reportPaths);
      const inputs = await readInputs(reportPaths, options.maxBytes);
      const reports = inputs.map((input) => parseReport(input, { maxBytes: options.maxBytes }));
      if (options.json)
        process.stdout.write(`${JSON.stringify(reports.map(reportSummary), null, 2)}\n`);
      else process.stdout.write(inspectTable(reports));
    });

  program
    .command("detect")
    .description("Print only the detected format for one report.")
    .argument("<report>", "Report path, or '-' for standard input")
    .action(async (reportPath: string) => {
      const [input] = await readInputs([reportPath], 100 * 1024 * 1024);
      if (!input) throw new Error("No report was supplied.");
      process.stdout.write(`${detectFormat(input.content, input.name)}\n`);
    });

  return program;
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

async function readFileLimited(path: string, maxBytes: number): Promise<string> {
  const handle = await readFile(path);
  if (handle.byteLength > maxBytes) {
    throw new Error(
      `${path} is ${handle.byteLength.toLocaleString()} bytes; the configured limit is ${maxBytes.toLocaleString()} bytes.`,
    );
  }
  return handle.toString("utf8");
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

async function atomicWrite(path: string, content: string): Promise<void> {
  const destination = resolve(path);
  await mkdir(dirname(destination), { recursive: true });
  const temporary = `${destination}.vulnfuse-${process.pid}.tmp`;
  try {
    await writeFile(temporary, content, "utf8");
    await rename(temporary, destination);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

function reportSummary(report: ParsedReport) {
  return {
    name: report.sourceName,
    format: report.format,
    tool: report.tool,
    findings: report.findings.length,
    warnings: report.warnings,
  };
}

function inspectTable(reports: ParsedReport[]): string {
  const lines = ["FORMAT       FINDINGS  TOOL                 REPORT"];
  for (const report of reports) {
    lines.push(
      `${report.format.padEnd(12)} ${String(report.findings.length).padStart(8)}  ${report.tool.slice(0, 20).padEnd(20)} ${report.sourceName}`,
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

await createProgram().parseAsync(process.argv);

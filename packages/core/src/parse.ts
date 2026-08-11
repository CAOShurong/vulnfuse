import type {
  CanonicalFinding,
  JsonValue,
  ParsedReport,
  ReportFormat,
  ReportInput,
} from "./model.js";
import { canonicalFindingSchema, vulnfuseDocumentSchema } from "./schema.js";
import { asArray, asRecord, asString } from "./utils.js";
import { parseCsv } from "./formats/csv.js";
import { parseCycloneDx } from "./formats/cyclonedx.js";
import { parseCycloneDxXml } from "./formats/cyclonedx-xml.js";
import { detectFormat } from "./formats/detect.js";
import { parseGrype } from "./formats/grype.js";
import { parseOpenVex } from "./formats/openvex.js";
import { parseOsv } from "./formats/osv.js";
import { parseSarif } from "./formats/sarif.js";
import { parseSnyk } from "./formats/snyk.js";
import { parseTrivy } from "./formats/trivy.js";

export const defaultMaxReportBytes = 100 * 1024 * 1024;

export interface ParseOptions {
  format?: ReportFormat;
  maxBytes?: number;
}

export function parseReport(input: ReportInput, options: ParseOptions = {}): ParsedReport {
  const byteLength = new TextEncoder().encode(input.content).byteLength;
  const maxBytes = options.maxBytes ?? defaultMaxReportBytes;
  if (byteLength > maxBytes) {
    throw new Error(
      `${input.name} is ${byteLength.toLocaleString()} bytes; the configured limit is ${maxBytes.toLocaleString()} bytes.`,
    );
  }
  const content = input.content.startsWith("\uFEFF") ? input.content.slice(1) : input.content;
  const format = options.format ?? detectFormat(content, input.name);
  if (format === "csv") return finalizeReport(parseCsv(content, input.name));
  if (format === "cyclonedx" && content.trimStart().startsWith("<")) {
    return finalizeReport(parseCycloneDxXml(content, input.name));
  }
  if (format === "unknown") {
    throw new Error(
      `Could not detect the report format for ${input.name}. Supported formats: SARIF, Trivy, Grype, Snyk, CycloneDX, OpenVEX, OSV-Scanner, CSV, and VulnFuse JSON.`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch (error) {
    throw new Error(
      `${input.name} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
  const root = asRecord(Array.isArray(parsed) ? parsed[0] : parsed);
  if (!root) throw new Error(`${input.name} must contain a JSON object.`);

  let report: ParsedReport;
  switch (format) {
    case "sarif":
      report = parseSarif(root, input.name);
      break;
    case "trivy":
      report = parseTrivy(root, input.name);
      break;
    case "grype":
      report = parseGrype(root, input.name);
      break;
    case "snyk":
      report = parseSnyk(root, input.name);
      break;
    case "cyclonedx":
      report = parseCycloneDx(root, input.name);
      break;
    case "openvex":
      report = parseOpenVex(root, input.name);
      break;
    case "osv-scanner":
      report = parseOsv(root, input.name);
      break;
    case "vulnfuse":
      report = parseVulnFuse(root, input.name);
      break;
  }
  return finalizeReport(report);
}

export function parseReports(inputs: ReportInput[], options: ParseOptions = {}): ParsedReport[] {
  return inputs.map((input) => parseReport(input, options));
}

function parseVulnFuse(root: Record<string, unknown>, reportName: string): ParsedReport {
  const shell = vulnfuseDocumentSchema.safeParse(root);
  if (!shell.success) throw new Error(`${reportName} is not a valid VulnFuse 1.0 document.`);
  const warnings: ParsedReport["warnings"] = [];
  const findings: CanonicalFinding[] = [];
  const reportTools: string[] = [];
  const reportToolVersions = new Map<string, Set<string>>();
  for (const reportValue of asArray(root["reports"])) {
    const report = asRecord(reportValue);
    const declaredTools = [
      ...asArray(report?.["tools"])
        .map(asString)
        .filter((tool): tool is string => Boolean(tool)),
      asString(report?.["tool"]),
    ].filter((tool): tool is string => Boolean(tool));
    for (const tool of declaredTools) {
      if (!reportTools.includes(tool)) reportTools.push(tool);
    }
    const toolVersions = asRecord(report?.["toolVersions"]);
    for (const [tool, versionValues] of Object.entries(toolVersions ?? {})) {
      for (const version of asArray(versionValues).map(asString)) {
        if (!version) continue;
        const values = reportToolVersions.get(tool) ?? new Set<string>();
        values.add(version);
        reportToolVersions.set(tool, values);
      }
    }
  }
  for (const [clusterIndex, clusterValue] of asArray(root["clusters"]).entries()) {
    const cluster = asRecord(clusterValue);
    for (const [memberIndex, member] of asArray(cluster?.["members"]).entries()) {
      const result = canonicalFindingSchema.safeParse(member);
      if (result.success) findings.push(result.data as CanonicalFinding);
      else {
        warnings.push({
          code: "vulnfuse.invalid-member",
          message: "A cluster member did not match the canonical finding schema.",
          path: `clusters[${clusterIndex}].members[${memberIndex}]`,
        });
      }
    }
  }
  const summary = asRecord(root["summary"]);
  const metadata: Record<string, JsonValue> = {
    originalClusters: Number(summary?.["clusters"] ?? asArray(root["clusters"]).length),
  };
  const tools = [
    ...new Set([
      ...asArray(summary?.["sourceTools"])
        .map(asString)
        .filter((tool): tool is string => Boolean(tool)),
      ...reportTools,
      ...findings.map((finding) => finding.source.tool),
    ]),
  ].sort();
  return {
    format: "vulnfuse",
    sourceName: reportName,
    tool: tools[0] ?? "VulnFuse",
    tools: tools.length > 0 ? tools : ["VulnFuse"],
    toolVersions: Object.fromEntries(
      [...reportToolVersions.entries()].map(([tool, values]) => [tool, [...values]] as const),
    ),
    findings,
    warnings,
    metadata,
  };
}

function finalizeReport(report: ParsedReport): ParsedReport {
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
  return {
    ...report,
    toolVersions: Object.fromEntries(
      [...versions.entries()]
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([tool, values]) => [tool, [...values].sort()] as const),
    ),
  };
}

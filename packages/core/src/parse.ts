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
import { detectFormat } from "./formats/detect.js";
import { parseGrype } from "./formats/grype.js";
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
  if (format === "csv") return parseCsv(content, input.name);
  if (format === "unknown") {
    throw new Error(
      `Could not detect the report format for ${input.name}. Supported formats: SARIF, Trivy, Grype, Snyk, CycloneDX, OSV-Scanner, CSV, and VulnFuse JSON.`,
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

  switch (format) {
    case "sarif":
      return parseSarif(root, input.name);
    case "trivy":
      return parseTrivy(root, input.name);
    case "grype":
      return parseGrype(root, input.name);
    case "snyk":
      return parseSnyk(root, input.name);
    case "cyclonedx":
      return parseCycloneDx(root, input.name);
    case "osv-scanner":
      return parseOsv(root, input.name);
    case "vulnfuse":
      return parseVulnFuse(root, input.name);
  }
}

export function parseReports(inputs: ReportInput[], options: ParseOptions = {}): ParsedReport[] {
  return inputs.map((input) => parseReport(input, options));
}

function parseVulnFuse(root: Record<string, unknown>, reportName: string): ParsedReport {
  const shell = vulnfuseDocumentSchema.safeParse(root);
  if (!shell.success) throw new Error(`${reportName} is not a valid VulnFuse 1.0 document.`);
  const warnings: ParsedReport["warnings"] = [];
  const findings: CanonicalFinding[] = [];
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
      ...findings.map((finding) => finding.source.tool),
    ]),
  ].sort();
  return {
    format: "vulnfuse",
    sourceName: reportName,
    tool: tools[0] ?? "VulnFuse",
    tools: tools.length > 0 ? tools : ["VulnFuse"],
    findings,
    warnings,
    metadata,
  };
}

import Papa from "papaparse";

import { extractIdentifiers, normalizeIdentifier, uniqueIdentifiers } from "../identifiers.js";
import type { FindingIdentifier, ParsedReport } from "../model.js";
import { asString, normalizeSeverity } from "../utils.js";
import { asset, cleanStrings, makeFinding, source } from "./common.js";

type CsvRow = Record<string, string | undefined>;

function value(row: CsvRow, ...names: string[]): string | undefined {
  const lower = Object.fromEntries(
    Object.entries(row).map(([key, item]) => [key.toLowerCase().trim(), item]),
  );
  for (const name of names) {
    const candidate = asString(lower[name.toLowerCase()]);
    if (candidate) return candidate;
  }
  return undefined;
}

export function parseCsv(content: string, reportName: string): ParsedReport {
  const parsed = Papa.parse<CsvRow>(content, {
    header: true,
    skipEmptyLines: "greedy",
    transformHeader: (header) => header.trim(),
  });
  const findings = parsed.data
    .map((row, index) => {
      const vulnerabilityId = value(
        row,
        "vulnerability_id",
        "vulnerability",
        "id",
        "cve",
        "advisory",
      );
      const title = value(row, "title", "summary", "name") ?? vulnerabilityId;
      if (!title) return undefined;
      const identifiers: FindingIdentifier[] = extractIdentifiers(
        [vulnerabilityId, title, value(row, "description", "details"), value(row, "aliases")],
        "related",
      );
      if (vulnerabilityId) {
        const identifier = normalizeIdentifier(vulnerabilityId, "primary");
        if (identifier) identifiers.push(identifier);
      }
      const componentName = value(row, "component", "package", "package_name", "dependency");
      const componentPurl = value(row, "purl", "package_url");
      const ecosystem = value(row, "ecosystem", "package_manager");
      const componentVersion = value(row, "version", "installed_version", "component_version");
      const assetName = value(row, "asset", "target", "repository", "image", "host");
      const uri = value(row, "path", "file", "uri", "location");
      const startLine = Number(value(row, "line", "start_line", "startline"));
      const fixedVersion = value(row, "fixed_version", "fixedin", "fix_version");
      const recommendation = value(row, "recommendation", "remediation", "fix");
      const tool = value(row, "tool", "scanner", "source") ?? "CSV";
      return makeFinding({
        source: source(tool, reportName, value(row, "tool_version", "scanner_version")),
        kind: csvKind(value(row, "kind", "category", "type")),
        title,
        ...(value(row, "description", "details")
          ? { description: value(row, "description", "details") }
          : {}),
        severity: normalizeSeverity(value(row, "severity", "priority", "cvss", "score")),
        identifiers: uniqueIdentifiers(identifiers),
        component: {
          ...(componentPurl ? { purl: componentPurl } : {}),
          ...(ecosystem ? { ecosystem } : {}),
          ...(componentName ? { name: componentName } : {}),
          ...(componentVersion ? { version: componentVersion } : {}),
          ...(uri ? { path: uri } : {}),
        },
        ...(assetName ? { asset: asset("unknown", assetName) } : {}),
        ...(uri
          ? {
              location: {
                uri,
                ...(Number.isInteger(startLine) && startLine > 0 ? { startLine } : {}),
              },
            }
          : {}),
        ...(value(row, "rule_id", "rule", "check_id")
          ? { ruleId: value(row, "rule_id", "rule", "check_id") }
          : {}),
        fingerprints: cleanStrings({
          fingerprint: value(row, "fingerprint", "hash", "finding_id"),
        }),
        remediation: {
          ...(fixedVersion ? { fixedVersion } : {}),
          ...(recommendation ? { recommendation } : {}),
        },
        references: (value(row, "references", "reference", "url") ?? "")
          .split(/[\s,;]+/)
          .filter((entry) => /^https?:\/\//i.test(entry)),
        properties: { row: index + 2 },
        nativeId: `${index}:${vulnerabilityId ?? title}`,
      });
    })
    .filter((entry): entry is NonNullable<typeof entry> => Boolean(entry));

  const tools = [...new Set(findings.map((finding) => finding.source.tool))].sort();
  return {
    format: "csv",
    sourceName: reportName,
    tool: findings[0]?.source.tool ?? "CSV",
    tools: tools.length > 0 ? tools : ["CSV"],
    findings,
    warnings: parsed.errors.map((error) => ({
      code: `csv.${error.code}`,
      message: error.message,
      ...(error.row !== undefined ? { path: `row ${error.row + 2}` } : {}),
    })),
    metadata: { rows: parsed.data.length },
  };
}

function csvKind(
  value: string | undefined,
): "sca" | "sast" | "container" | "iac" | "secret" | "dast" | "license" | "unknown" {
  const normalized = value?.trim().toLowerCase();
  return normalized &&
    ["sca", "sast", "container", "iac", "secret", "dast", "license"].includes(normalized)
    ? (normalized as "sca" | "sast" | "container" | "iac" | "secret" | "dast" | "license")
    : "unknown";
}

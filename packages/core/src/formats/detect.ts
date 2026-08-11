import type { ReportFormat } from "../model.js";
import { asArray, asRecord, asString } from "../utils.js";

export function detectFormat(content: string, fileName = "report"): ReportFormat {
  const trimmed = content.trim();
  if (fileName.toLowerCase().endsWith(".csv")) return "csv";
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
    return looksLikeDelimitedText(trimmed) ? "csv" : "unknown";
  }
  let value: unknown;
  try {
    value = JSON.parse(trimmed);
  } catch {
    return fileName.toLowerCase().endsWith(".csv") ? "csv" : "unknown";
  }
  const root = asRecord(Array.isArray(value) ? value[0] : value);
  if (!root) return "unknown";
  if (
    asString(root["$schema"])?.toLowerCase().includes("sarif") ||
    (root["version"] === "2.1.0" && Array.isArray(root["runs"]))
  ) {
    return "sarif";
  }
  if (asString(root["bomFormat"])?.toLowerCase() === "cyclonedx") return "cyclonedx";
  if (openVexContext(root["@context"]) && Array.isArray(root["statements"])) return "openvex";
  if (Array.isArray(root["matches"]) && root["descriptor"] !== undefined) return "grype";
  if (
    Array.isArray(root["Results"]) &&
    (root["SchemaVersion"] !== undefined || root["ArtifactName"] !== undefined)
  )
    return "trivy";
  if (
    root["schemaVersion"] === "1.0" &&
    Array.isArray(root["clusters"]) &&
    root["summary"] !== undefined
  )
    return "vulnfuse";
  if (Array.isArray(root["results"]) && osvShape(root)) return "osv-scanner";
  if (
    Array.isArray(root["vulnerabilities"]) ||
    asRecord(root["issues"])?.["vulnerabilities"] !== undefined
  )
    return "snyk";
  return "unknown";
}

function openVexContext(value: unknown): boolean {
  return [value, ...asArray(value)].some((candidate) =>
    /^https:\/\/openvex\.dev\/ns\/v\d+(?:\.\d+){0,2}\/?$/i.test(asString(candidate) ?? ""),
  );
}

function looksLikeDelimitedText(value: string): boolean {
  if (!value || hasUnsafeControlCharacter(value)) return false;
  const lines = value
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .slice(0, 3);
  if (lines.length < 2) return false;
  return [",", "\t", ";"].some((delimiter) => {
    const headerColumns = lines[0]?.split(delimiter).length ?? 0;
    return headerColumns >= 2 && lines.slice(1).some((line) => line.split(delimiter).length >= 2);
  });
}

function hasUnsafeControlCharacter(value: string): boolean {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 32 && code !== 9 && code !== 10 && code !== 13) return true;
  }
  return false;
}

function osvShape(root: Record<string, unknown>): boolean {
  const firstResult = asRecord(asArray(root["results"])[0]);
  if (!firstResult) return true;
  const firstPackage = asRecord(asArray(firstResult["packages"])[0]);
  return (
    Array.isArray(firstResult["packages"]) &&
    (!firstPackage || Array.isArray(firstPackage["vulnerabilities"]))
  );
}

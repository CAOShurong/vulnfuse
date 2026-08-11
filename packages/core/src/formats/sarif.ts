import { extractIdentifiers, normalizeIdentifier, uniqueIdentifiers } from "../identifiers.js";
import type {
  CanonicalFinding,
  FindingIdentifier,
  FindingKind,
  FindingSuppression,
  JsonValue,
  ParsedReport,
} from "../model.js";
import {
  asArray,
  asJsonValue,
  asNumber,
  asRecord,
  asString,
  normalizeSeverity,
  safeHttpReference,
} from "../utils.js";
import { asset, makeFinding, source } from "./common.js";

function sarifKind(tags: string[], properties: Record<string, unknown>): FindingKind {
  const text = [...tags, asString(properties["category"]) ?? "", asString(properties["kind"]) ?? ""]
    .join(" ")
    .toLowerCase();
  if (/secret|credential/.test(text)) return "secret";
  if (/infrastructure|iac|terraform|kubernetes/.test(text)) return "iac";
  if (/dependency|sca|package|container/.test(text))
    return text.includes("container") ? "container" : "sca";
  if (/license/.test(text)) return "license";
  if (/dynamic|dast/.test(text)) return "dast";
  return "sast";
}

export function parseSarif(root: Record<string, unknown>, reportName: string): ParsedReport {
  const findings: CanonicalFinding[] = [];
  const warnings: ParsedReport["warnings"] = [];
  const reportTools: string[] = [];

  for (const [runIndex, runValue] of asArray(root["runs"]).entries()) {
    const run = asRecord(runValue);
    const tool = asRecord(run?.["tool"]);
    const driver = asRecord(tool?.["driver"]);
    const toolName = asString(driver?.["name"]) ?? "SARIF tool";
    if (!reportTools.includes(toolName)) reportTools.push(toolName);
    const toolVersion = asString(driver?.["semanticVersion"]) ?? asString(driver?.["version"]);
    const rules = new Map<string, Record<string, unknown>>();
    for (const ruleValue of asArray(driver?.["rules"])) {
      const rule = asRecord(ruleValue);
      const id = asString(rule?.["id"]);
      if (rule && id) rules.set(id, rule);
    }

    for (const [resultIndex, resultValue] of asArray(run?.["results"]).entries()) {
      const result = asRecord(resultValue);
      if (!result) continue;
      const ruleId = asString(result["ruleId"]);
      const rule = ruleId ? rules.get(ruleId) : undefined;
      const ruleProperties = asRecord(rule?.["properties"]) ?? {};
      const resultProperties = asRecord(result["properties"]) ?? {};
      const suppression = parseSuppressions(
        result["suppressions"],
        runIndex,
        resultIndex,
        warnings,
      );
      const message = asRecord(result["message"]);
      const title =
        asString(message?.["text"]) ??
        asString(message?.["markdown"]) ??
        asString(asRecord(rule?.["shortDescription"])?.["text"]) ??
        ruleId ??
        "SARIF finding";
      const description =
        asString(asRecord(rule?.["fullDescription"])?.["text"]) ??
        asString(asRecord(rule?.["help"])?.["text"]);
      const tags = asArray(ruleProperties["tags"])
        .map(asString)
        .filter((value): value is string => Boolean(value));
      const identifiers: FindingIdentifier[] = extractIdentifiers(
        [ruleId, title, description, ...tags],
        "related",
      );
      if (ruleId) {
        const identifier = normalizeIdentifier(ruleId, "rule", "RULE");
        if (identifier) identifiers.push(identifier);
      }
      const locationEntry = asRecord(asArray(result["locations"])[0]);
      const physical = asRecord(locationEntry?.["physicalLocation"]);
      const artifactLocation = asRecord(physical?.["artifactLocation"]);
      const region = asRecord(physical?.["region"]);
      const logical = asRecord(asArray(locationEntry?.["logicalLocations"])[0]);
      const uri = asString(artifactLocation?.["uri"]);
      const fileAsset = asset("file", uri);
      const startLine = asNumber(region?.["startLine"]);
      const endLine = asNumber(region?.["endLine"]);
      const startColumn = asNumber(region?.["startColumn"]);
      const symbol = asString(logical?.["fullyQualifiedName"]);
      const fingerprints = {
        ...stringRecord(asRecord(result["fingerprints"])),
        ...stringRecord(asRecord(result["partialFingerprints"])),
      };
      const securityScore = asNumber(ruleProperties["security-severity"]);
      const severity =
        securityScore !== undefined
          ? normalizeSeverity(securityScore)
          : normalizeSeverity(result["level"]);
      const references = [
        safeHttpReference(asRecord(rule?.["helpUri"]) ?? rule?.["helpUri"]),
        safeHttpReference(rule?.["helpUri"]),
        ...asArray(resultProperties["references"]).map(safeHttpReference),
      ].filter((value): value is string => Boolean(value));
      const rawSuppressions = asJsonValue(result["suppressions"]);
      const resultKind = parseResultKind(result, runIndex, resultIndex, warnings);
      const properties = asJsonValue({
        ...resultProperties,
        "sarif.resultKind": resultKind.value,
        ...(rawSuppressions !== undefined ? { "sarif.suppressions": rawSuppressions } : {}),
      });

      findings.push(
        makeFinding({
          source: source(toolName, reportName, toolVersion, `run-${runIndex + 1}`),
          kind: sarifKind(tags, resultProperties),
          title,
          ...(description ? { description } : {}),
          severity,
          identifiers: uniqueIdentifiers(identifiers),
          ...(uri ? { component: { path: uri }, ...(fileAsset ? { asset: fileAsset } : {}) } : {}),
          ...(uri || region || logical
            ? {
                location: {
                  ...(uri ? { uri } : {}),
                  ...(startLine !== undefined ? { startLine } : {}),
                  ...(endLine !== undefined ? { endLine } : {}),
                  ...(startColumn !== undefined ? { startColumn } : {}),
                  ...(symbol ? { symbol } : {}),
                },
              }
            : {}),
          ...(ruleId ? { ruleId } : {}),
          fingerprints,
          suppressed: suppression.suppressed,
          nonFinding: resultKind.nonFinding,
          suppressions: suppression.suppressions,
          references,
          ...(properties && !Array.isArray(properties) && typeof properties === "object"
            ? { properties: properties as Record<string, JsonValue> }
            : {}),
          nativeId: `${runIndex}:${resultIndex}:${asString(result["guid"]) ?? ruleId ?? title}`,
        }),
      );
    }
  }

  if (asArray(root["runs"]).length === 0) {
    warnings.push({ code: "sarif.no-runs", message: "The SARIF document has no runs." });
  }
  return {
    format: "sarif",
    sourceName: reportName,
    tool: reportTools[0] ?? "SARIF",
    tools: reportTools.length > 0 ? [...reportTools].sort() : ["SARIF"],
    findings,
    warnings,
    metadata: { version: asString(root["version"]) ?? "unknown" },
  };
}

const sarifResultKinds = new Set([
  "pass",
  "open",
  "informational",
  "notApplicable",
  "review",
  "fail",
]);

function parseResultKind(
  result: Record<string, unknown>,
  runIndex: number,
  resultIndex: number,
  warnings: ParsedReport["warnings"],
): { value: JsonValue; nonFinding: boolean } {
  if (!Object.prototype.hasOwnProperty.call(result, "kind")) {
    return { value: "fail", nonFinding: false };
  }

  const raw = result["kind"];
  const value = asJsonValue(raw) ?? null;
  if (typeof raw !== "string" || !sarifResultKinds.has(raw)) {
    warnings.push({
      code: "sarif.invalid-result-kind",
      message: "A SARIF result kind was invalid, so the result remains active.",
      path: `runs[${runIndex}].results[${resultIndex}].kind`,
    });
    return { value, nonFinding: false };
  }

  if (raw !== "fail" && result["level"] !== undefined && result["level"] !== "none") {
    warnings.push({
      code: "sarif.inconsistent-result-kind",
      message:
        "A non-fail SARIF result kind had a non-none level, so the contradictory result remains active.",
      path: `runs[${runIndex}].results[${resultIndex}].kind`,
    });
    return { value: raw, nonFinding: false };
  }

  return {
    value: raw,
    nonFinding: raw === "pass" || raw === "informational" || raw === "notApplicable",
  };
}

function parseSuppressions(
  value: unknown,
  runIndex: number,
  resultIndex: number,
  warnings: ParsedReport["warnings"],
): { suppressed: boolean; suppressions: FindingSuppression[] } {
  if (value === undefined || value === null) return { suppressed: false, suppressions: [] };
  const raw = Array.isArray(value) ? value : undefined;
  if (!raw) {
    warnings.push({
      code: "sarif.invalid-suppression",
      message: "A SARIF suppressions value was not an array, so the finding remains active.",
      path: `runs[${runIndex}].results[${resultIndex}].suppressions`,
    });
    return { suppressed: false, suppressions: [] };
  }

  const suppressions: FindingSuppression[] = [];
  let invalid = false;
  for (const [suppressionIndex, suppressionValue] of raw.entries()) {
    const suppression = asRecord(suppressionValue);
    const kind = asString(suppression?.["kind"]);
    const status = asString(suppression?.["status"]);
    const validKind = kind === "inSource" || kind === "external";
    const validStatus =
      status === undefined ||
      status === "accepted" ||
      status === "underReview" ||
      status === "rejected";
    if (!suppression || !validKind || !validStatus) {
      invalid = true;
      warnings.push({
        code: "sarif.invalid-suppression",
        message:
          "A SARIF suppression had an invalid kind or status, so the finding remains active.",
        path: `runs[${runIndex}].results[${resultIndex}].suppressions[${suppressionIndex}]`,
      });
      continue;
    }
    const justification = asString(suppression["justification"]);
    suppressions.push({
      kind,
      ...(status ? { status } : {}),
      ...(justification ? { justification } : {}),
    });
  }

  const contested = suppressions.some(
    (suppression) => suppression.status === "underReview" || suppression.status === "rejected",
  );
  return {
    suppressed: !invalid && suppressions.length > 0 && !contested,
    suppressions,
  };
}

function stringRecord(value: Record<string, unknown> | undefined): Record<string, string> {
  if (!value) return {};
  return Object.fromEntries(
    Object.entries(value)
      .map(([key, item]) => [key, asString(item)] as const)
      .filter((entry): entry is readonly [string, string] => Boolean(entry[1])),
  );
}

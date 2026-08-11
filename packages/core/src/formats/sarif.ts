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

type SarifLocationResolution = {
  uri: string | undefined;
  properties: Record<string, JsonValue>;
};

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
  const runHealth: JsonValue[] = [];

  for (const [runIndex, runValue] of asArray(root["runs"]).entries()) {
    const run = asRecord(runValue);
    const tool = asRecord(run?.["tool"]);
    const driver = asRecord(tool?.["driver"]);
    const toolName = asString(driver?.["name"]) ?? "SARIF tool";
    if (!reportTools.includes(toolName)) reportTools.push(toolName);
    const toolVersion = asString(driver?.["semanticVersion"]) ?? asString(driver?.["version"]);
    const health = inspectRunHealth(run, runIndex, toolName, warnings);
    const healthValue = asJsonValue(health);
    if (healthValue !== undefined) runHealth.push(healthValue);
    const originalUriBaseIds = asRecord(run?.["originalUriBaseIds"]) ?? {};
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
      const rawUri = asString(artifactLocation?.["uri"]);
      const uriBaseId = asString(artifactLocation?.["uriBaseId"]);
      const resolvedLocation = resolvePortableSarifLocation({
        uri: rawUri,
        uriBaseId,
        originalUriBaseIds,
        runIndex,
        resultIndex,
        warnings,
      });
      const uri = resolvedLocation.uri;
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
        ...resolvedLocation.properties,
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
    metadata: { version: asString(root["version"]) ?? "unknown", runHealth },
  };
}

function resolvePortableSarifLocation(options: {
  uri: string | undefined;
  uriBaseId: string | undefined;
  originalUriBaseIds: Record<string, unknown>;
  runIndex: number;
  resultIndex: number;
  warnings: ParsedReport["warnings"];
}): SarifLocationResolution {
  const { uri, uriBaseId, originalUriBaseIds, runIndex, resultIndex, warnings } = options;
  if (!uri || !uriBaseId) return { uri, properties: {} };

  const locationPath = `runs[${runIndex}].results[${resultIndex}].locations[0].physicalLocation.artifactLocation`;
  const baseEvidence = { "sarif.locationUriBaseId": uriBaseId };
  if (isAbsoluteUri(uri)) {
    warnings.push({
      code: "sarif.invalid-uri-base",
      message:
        "A SARIF artifactLocation combined an absolute URI with uriBaseId, so VulnFuse preserved the original URI without applying the base.",
      path: `${locationPath}.uriBaseId`,
    });
    return {
      uri,
      properties: { ...baseEvidence, "sarif.locationResolution": "unresolved" },
    };
  }

  const prefixes: string[] = [];
  const visited = new Set<string>();
  let current = uriBaseId;
  let resolution: "redacted-root" | "absolute-root-omitted" | undefined;

  while (true) {
    if (visited.has(current)) {
      warnings.push({
        code: "sarif.circular-uri-base",
        message:
          "A SARIF URI-base chain contains a loop, so VulnFuse preserved the original relative location.",
        path: `${locationPath}.uriBaseId`,
      });
      return {
        uri,
        properties: { ...baseEvidence, "sarif.locationResolution": "unresolved" },
      };
    }
    if (visited.size >= 100) {
      warnings.push({
        code: "sarif.invalid-uri-base",
        message:
          "A SARIF URI-base chain exceeded the 100-entry safety limit, so VulnFuse preserved the original relative location.",
        path: `${locationPath}.uriBaseId`,
      });
      return {
        uri,
        properties: { ...baseEvidence, "sarif.locationResolution": "unresolved" },
      };
    }
    visited.add(current);

    if (!Object.prototype.hasOwnProperty.call(originalUriBaseIds, current)) {
      warnings.push({
        code: "sarif.unknown-uri-base",
        message:
          "A SARIF artifactLocation references an unknown URI base, so VulnFuse preserved the original relative location.",
        path: `${locationPath}.uriBaseId`,
      });
      return {
        uri,
        properties: { ...baseEvidence, "sarif.locationResolution": "unresolved" },
      };
    }

    const base = asRecord(originalUriBaseIds[current]);
    const basePath = `runs[${runIndex}].originalUriBaseIds.${current}`;
    if (!base) {
      return unresolvedInvalidBase(
        uri,
        baseEvidence,
        warnings,
        basePath,
        "A SARIF originalUriBaseIds entry was not an object",
      );
    }

    const rawBaseUri = base["uri"];
    const baseUri = asString(rawBaseUri);
    const rawParent = base["uriBaseId"];
    const parent = asString(rawParent);
    if (rawBaseUri !== undefined && baseUri === undefined) {
      return unresolvedInvalidBase(
        uri,
        baseEvidence,
        warnings,
        `${basePath}.uri`,
        "A SARIF URI base had a non-string uri",
      );
    }
    if (rawParent !== undefined && parent === undefined) {
      return unresolvedInvalidBase(
        uri,
        baseEvidence,
        warnings,
        `${basePath}.uriBaseId`,
        "A SARIF URI base had a non-string uriBaseId",
      );
    }

    if (baseUri === undefined) {
      if (parent !== undefined) {
        return unresolvedInvalidBase(
          uri,
          baseEvidence,
          warnings,
          `${basePath}.uriBaseId`,
          "A SARIF URI base without a uri also declared another uriBaseId",
        );
      }
      resolution = "redacted-root";
      break;
    }

    const invalidReason = invalidUriBaseReason(baseUri);
    if (invalidReason) {
      return unresolvedInvalidBase(
        uri,
        baseEvidence,
        warnings,
        `${basePath}.uri`,
        `A SARIF URI base ${invalidReason}`,
      );
    }

    if (isAbsoluteUri(baseUri)) {
      if (parent !== undefined) {
        return unresolvedInvalidBase(
          uri,
          baseEvidence,
          warnings,
          `${basePath}.uriBaseId`,
          "An absolute SARIF URI base also declared another uriBaseId",
        );
      }
      resolution = "absolute-root-omitted";
      break;
    }

    if (!parent) {
      return unresolvedInvalidBase(
        uri,
        baseEvidence,
        warnings,
        `${basePath}.uriBaseId`,
        "A relative SARIF URI base did not declare its parent uriBaseId",
      );
    }
    prefixes.unshift(baseUri);
    current = parent;
  }

  const resolvedUri = `${prefixes.join("")}${uri}`;
  return {
    uri: resolvedUri,
    properties: {
      ...baseEvidence,
      ...(resolvedUri !== uri ? { "sarif.originalLocationUri": uri } : {}),
      "sarif.locationResolution": resolution ?? "unresolved",
    },
  };
}

function unresolvedInvalidBase(
  uri: string,
  evidence: Record<string, JsonValue>,
  warnings: ParsedReport["warnings"],
  path: string,
  reason: string,
): SarifLocationResolution {
  warnings.push({
    code: "sarif.invalid-uri-base",
    message: `${reason}, so VulnFuse preserved the original relative location.`,
    path,
  });
  return {
    uri,
    properties: { ...evidence, "sarif.locationResolution": "unresolved" },
  };
}

function invalidUriBaseReason(uri: string): string | undefined {
  if (!uri.endsWith("/")) return "did not end with a forward slash";
  if (uri.includes("?") || uri.includes("#")) return "contained a query or fragment";
  if (uri.includes("\\")) return "contained a backslash instead of URI path separators";
  for (const segment of uri.split("/")) {
    try {
      if (decodeURIComponent(segment) === "..") return "contained a '..' path segment";
    } catch {
      return "contained malformed percent encoding";
    }
  }
  return undefined;
}

function isAbsoluteUri(uri: string): boolean {
  return /^[a-z][a-z\d+.-]*:/i.test(uri);
}

function inspectRunHealth(
  run: Record<string, unknown> | undefined,
  runIndex: number,
  toolName: string,
  warnings: ParsedReport["warnings"],
): Record<string, JsonValue> {
  const rawResults = run?.["results"];
  const externalReferences = asRecord(run?.["externalPropertyFileReferences"]);
  const externalResults = asArray(externalReferences?.["results"]);
  let resultsState: "inline" | "unavailable" | "external" | "invalid" = "inline";
  let resultCount = 0;
  if (Array.isArray(rawResults)) {
    resultCount = rawResults.length;
  } else if (rawResults === null || rawResults === undefined) {
    if (externalResults.length > 0) {
      resultsState = "external";
      warnings.push({
        code: "sarif.external-results-unsupported",
        message:
          "This SARIF run references external results that VulnFuse does not fetch or resolve, so its visible findings may be incomplete.",
        path: `runs[${runIndex}].externalPropertyFileReferences.results`,
      });
    } else {
      resultsState = "unavailable";
      warnings.push({
        code: "sarif.results-unavailable",
        message:
          "This SARIF run has null or absent results, which the SARIF specification treats as a tool that failed to start or begin analysis.",
        path: `runs[${runIndex}].results`,
      });
    }
  } else {
    resultsState = "invalid";
    warnings.push({
      code: "sarif.invalid-results",
      message:
        "This SARIF run has a non-array results value, so VulnFuse cannot treat its visible findings as complete.",
      path: `runs[${runIndex}].results`,
    });
  }

  const invocations = asArray(run?.["invocations"]);
  let failedInvocations = 0;
  let unknownInvocations = 0;
  let errorNotifications = 0;
  for (const [invocationIndex, invocationValue] of invocations.entries()) {
    const invocation = asRecord(invocationValue);
    if (!invocation) {
      unknownInvocations += 1;
      warnings.push({
        code: "sarif.invalid-invocation",
        message:
          "A SARIF invocation was not an object, so its execution status and result completeness are unknown.",
        path: `runs[${runIndex}].invocations[${invocationIndex}]`,
      });
      continue;
    }
    const executionSuccessful = invocation["executionSuccessful"];
    if (executionSuccessful === false) {
      failedInvocations += 1;
      warnings.push({
        code: "sarif.execution-failed",
        message:
          "The SARIF producer declared this analysis invocation unsuccessful; retained findings may be partial.",
        path: `runs[${runIndex}].invocations[${invocationIndex}].executionSuccessful`,
      });
    } else if (typeof executionSuccessful !== "boolean") {
      unknownInvocations += 1;
      warnings.push({
        code: "sarif.execution-status-unknown",
        message:
          "A SARIF invocation omitted a valid boolean executionSuccessful value, so result completeness is unknown.",
        path: `runs[${runIndex}].invocations[${invocationIndex}].executionSuccessful`,
      });
    }
    errorNotifications += inspectNotificationErrors(
      invocation["toolExecutionNotifications"],
      "tool-execution",
      runIndex,
      invocationIndex,
      warnings,
    );
    errorNotifications += inspectNotificationErrors(
      invocation["toolConfigurationNotifications"],
      "tool-configuration",
      runIndex,
      invocationIndex,
      warnings,
    );
  }

  return {
    run: runIndex + 1,
    tool: toolName,
    resultsState,
    resultCount,
    invocationCount: invocations.length,
    failedInvocations,
    unknownInvocations,
    errorNotifications,
  };
}

function inspectNotificationErrors(
  value: unknown,
  kind: "tool-execution" | "tool-configuration",
  runIndex: number,
  invocationIndex: number,
  warnings: ParsedReport["warnings"],
): number {
  let errors = 0;
  const property =
    kind === "tool-execution" ? "toolExecutionNotifications" : "toolConfigurationNotifications";
  for (const [notificationIndex, notificationValue] of asArray(value).entries()) {
    const notification = asRecord(notificationValue);
    if (asString(notification?.["level"]) !== "error") continue;
    errors += 1;
    const descriptor = asString(asRecord(notification?.["descriptor"])?.["id"]);
    const messageRecord = asRecord(notification?.["message"]);
    const message = asString(messageRecord?.["text"]) ?? asString(messageRecord?.["markdown"]);
    const detail = [descriptor, message].filter(Boolean).join(": ").slice(0, 500);
    warnings.push({
      code:
        kind === "tool-execution" ? "sarif.tool-execution-error" : "sarif.tool-configuration-error",
      message: `The SARIF producer reported an error-level ${kind.replace("-", " ")} notification${detail ? `: ${detail}` : ". Retained findings may be incomplete."}`,
      path: `runs[${runIndex}].invocations[${invocationIndex}].${property}[${notificationIndex}]`,
    });
  }
  return errors;
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

import { extractIdentifiers, normalizeIdentifier, uniqueIdentifiers } from "../identifiers.js";
import type { CanonicalFinding, FindingIdentifier, JsonValue, ParsedReport } from "../model.js";
import {
  asArray,
  asJsonValue,
  asNumber,
  asRecord,
  asString,
  canonicalizePurl,
  maxSeverity,
  normalizeSeverity,
  safeHttpReference,
} from "../utils.js";
import { asset, makeFinding, source } from "./common.js";

export function parseCycloneDx(root: Record<string, unknown>, reportName: string): ParsedReport {
  const findings: CanonicalFinding[] = [];
  const components = new Map<string, Record<string, unknown>>();
  for (const value of asArray(root["components"])) {
    const component = asRecord(value);
    const ref = asString(component?.["bom-ref"]);
    if (component && ref) components.set(ref, component);
  }
  const metadata = asRecord(root["metadata"]);
  const rootComponent = asRecord(metadata?.["component"]);
  const rootName = asString(rootComponent?.["name"]);
  const rootAsset = asset("application", rootName ?? asString(root["serialNumber"]));
  const tool = cycloneTool(metadata);
  const toolName = tool?.name ?? "CycloneDX";

  for (const [index, value] of asArray(root["vulnerabilities"]).entries()) {
    const vulnerability = asRecord(value);
    if (!vulnerability) continue;
    const vulnerabilityId = asString(vulnerability["id"]);
    const referenceIds = asArray(vulnerability["references"])
      .map((entry) => asString(asRecord(entry)?.["id"]))
      .filter((entry): entry is string => Boolean(entry));
    const identifiers: FindingIdentifier[] = extractIdentifiers(
      [
        vulnerabilityId,
        ...referenceIds,
        asString(vulnerability["description"]),
        asString(vulnerability["detail"]),
      ],
      "related",
    );
    if (vulnerabilityId) {
      const identifier = normalizeIdentifier(vulnerabilityId, "primary");
      if (identifier) identifiers.push(identifier);
    }
    for (const cwe of asArray(vulnerability["cwes"]).map(asString)) {
      if (!cwe) continue;
      const identifier = normalizeIdentifier(
        cwe.startsWith("CWE-") ? cwe : `CWE-${cwe}`,
        "weakness",
        "CWE",
      );
      if (identifier) identifiers.push(identifier);
    }
    const ratings = asArray(vulnerability["ratings"])
      .map(asRecord)
      .filter((entry): entry is Record<string, unknown> => Boolean(entry));
    const ratingSeverities = ratings.map((rating) =>
      normalizeSeverity(rating["severity"] ?? asNumber(rating["score"])),
    );
    const analysis = asRecord(vulnerability["analysis"]);
    const recommendation = asString(vulnerability["recommendation"] ?? analysis?.["detail"]);
    const properties = asJsonValue({
      source: vulnerability["source"],
      ratings: vulnerability["ratings"],
      analysis: vulnerability["analysis"],
      affects: vulnerability["affects"],
    });

    const affectedEntries = asArray(vulnerability["affects"])
      .map(asRecord)
      .filter((entry): entry is Record<string, unknown> => Boolean(entry));
    const targets: Array<Record<string, unknown> | undefined> =
      affectedEntries.length > 0 ? affectedEntries : [undefined];

    for (const [affectedIndex, affected] of targets.entries()) {
      const affectedRef = asString(affected?.["ref"]);
      const component = affectedRef ? components.get(affectedRef) : undefined;
      const version = affectedVersion(affected) ?? asString(component?.["version"]);
      const componentPurl =
        canonicalizePurl(asString(component?.["purl"])) ?? purlFromAffectedRef(affectedRef);
      const componentGroup = asString(component?.["group"]);
      const componentName = asString(component?.["name"]);
      const componentType = asString(component?.["type"]);
      const fixedVersion = affectedFixedVersion(affected);
      const targetSuffix = targets.length > 1 ? `:${affectedIndex}` : "";

      findings.push(
        makeFinding({
          source: source(toolName, reportName, tool?.version),
          kind: "sca",
          title: vulnerabilityId
            ? `${vulnerabilityId} in ${componentName ?? componentPurl ?? affectedRef ?? "component"}`
            : "CycloneDX vulnerability",
          ...(asString(vulnerability["description"] ?? vulnerability["detail"])
            ? { description: asString(vulnerability["description"] ?? vulnerability["detail"]) }
            : {}),
          severity: ratingSeverities.length > 0 ? maxSeverity(ratingSeverities) : "unknown",
          identifiers: uniqueIdentifiers(identifiers),
          component: {
            ...(componentPurl ? { purl: componentPurl } : {}),
            ...(componentGroup ? { ecosystem: componentGroup } : {}),
            ...(componentName ? { name: componentName } : {}),
            ...(version ? { version } : {}),
            ...(componentType ? { type: componentType } : {}),
          },
          ...(rootAsset ? { asset: rootAsset } : {}),
          remediation: {
            ...(fixedVersion ? { fixedVersion } : {}),
            ...(recommendation ? { recommendation } : {}),
          },
          references: [
            safeHttpReference(asRecord(vulnerability["source"])?.["url"]),
            ...asArray(vulnerability["references"])
              .map((entry) => asRecord(entry)?.["url"])
              .map(safeHttpReference),
            ...asArray(vulnerability["advisories"])
              .map((entry) => asRecord(entry)?.["url"])
              .map(safeHttpReference),
          ].filter((entry): entry is string => Boolean(entry)),
          ...(properties && !Array.isArray(properties) && typeof properties === "object"
            ? { properties: properties as Record<string, JsonValue> }
            : {}),
          nativeId: `${index}:${vulnerabilityId ?? "finding"}:${affectedRef ?? "component"}${targetSuffix}`,
        }),
      );
    }
  }

  return {
    format: "cyclonedx",
    sourceName: reportName,
    tool: toolName,
    tools: [toolName],
    toolVersions: tool?.version ? { [toolName]: [tool.version] } : {},
    findings,
    warnings:
      findings.length === 0
        ? [
            {
              code: "cyclonedx.no-vulnerabilities",
              message: "The CycloneDX document has no vulnerability records.",
            },
          ]
        : [],
    metadata: {
      specVersion: asString(root["specVersion"]) ?? "unknown",
      ...(asString(root["serialNumber"])
        ? { serialNumber: asString(root["serialNumber"]) as string }
        : {}),
    },
  };
}

const BOM_LINK_ELEMENT =
  /^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/[1-9][0-9]*#(.+)$/;

function purlFromAffectedRef(ref: string | undefined): string | undefined {
  const direct = canonicalizePurl(ref);
  if (direct) return direct;

  const fragment = ref?.match(BOM_LINK_ELEMENT)?.[1];
  if (!fragment) return undefined;
  const encoded = canonicalizePurl(fragment);
  if (encoded) return encoded;

  try {
    return canonicalizePurl(decodeURIComponent(fragment));
  } catch {
    return undefined;
  }
}

function cycloneTool(
  metadata: Record<string, unknown> | undefined,
): { name: string; version?: string } | undefined {
  const tools = metadata ? metadata["tools"] : undefined;
  const structured = asRecord(tools);
  const toolArray = Array.isArray(tools)
    ? tools
    : [...asArray(structured?.["components"]), ...asArray(structured?.["services"])];
  const first = asRecord(toolArray[0]);
  const name = asString(first?.["name"]);
  if (!name) return undefined;
  const version = asString(first?.["version"]);
  return { name, ...(version ? { version } : {}) };
}

function affectedVersion(affected: Record<string, unknown> | undefined): string | undefined {
  const range = asRecord(asArray(affected?.["versions"])[0]);
  return asString(range?.["version"] ?? range?.["range"]);
}

function affectedFixedVersion(affected: Record<string, unknown> | undefined): string | undefined {
  const versions = asArray(affected?.["versions"])
    .map(asRecord)
    .filter((entry): entry is Record<string, unknown> => Boolean(entry))
    .filter((entry) => asString(entry["status"])?.toLowerCase() === "unaffected")
    .map((entry) => asString(entry["version"]))
    .filter((entry): entry is string => Boolean(entry));
  return versions.length > 0 ? versions.join(", ") : undefined;
}

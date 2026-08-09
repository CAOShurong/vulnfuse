import { extractIdentifiers, normalizeIdentifier, uniqueIdentifiers } from "../identifiers.js";
import type { CanonicalFinding, FindingIdentifier, JsonValue, ParsedReport } from "../model.js";
import {
  asArray,
  asJsonValue,
  asRecord,
  asString,
  normalizeSeverity,
  safeHttpReference,
} from "../utils.js";
import { asset, cleanStrings, makeFinding, source } from "./common.js";

export function parseGrype(root: Record<string, unknown>, reportName: string): ParsedReport {
  const findings: CanonicalFinding[] = [];
  const descriptor = asRecord(root["descriptor"]);
  const version = asString(descriptor?.["version"]);
  const sourceDescription = asRecord(root["source"]);
  const target = asString(
    sourceDescription?.["target"] ?? sourceDescription?.["name"] ?? sourceDescription?.["path"],
  );
  const sourceType = asString(sourceDescription?.["type"])?.toLowerCase();
  const targetAsset = asset(sourceType?.includes("image") ? "image" : "repository", target);

  for (const [matchIndex, matchValue] of asArray(root["matches"]).entries()) {
    const match = asRecord(matchValue);
    const vulnerability = asRecord(match?.["vulnerability"]);
    const artifactRecord = asRecord(match?.["artifact"]);
    if (!match || !vulnerability || !artifactRecord) continue;
    const vulnerabilityId = asString(vulnerability["id"]);
    const identifiers: FindingIdentifier[] = extractIdentifiers(
      [
        vulnerabilityId,
        asString(vulnerability["description"]),
        ...asArray(vulnerability["aliases"]).map(asString),
      ],
      "alias",
    );
    if (vulnerabilityId) {
      const identifier = normalizeIdentifier(vulnerabilityId, "primary");
      if (identifier) identifiers.push(identifier);
    }
    const artifactName = asString(artifactRecord["name"]);
    const artifactVersion = asString(artifactRecord["version"]);
    const artifactType = asString(artifactRecord["type"]);
    const artifactLanguage = asString(artifactRecord["language"]);
    const purl = asString(artifactRecord["purl"]);
    const firstLocation = asRecord(asArray(artifactRecord["locations"])[0]);
    const locationPath = asString(firstLocation?.["path"] ?? firstLocation?.["realPath"]);
    const fix = asRecord(vulnerability["fix"]);
    const fixedVersions = asArray(fix?.["versions"])
      .map(asString)
      .filter((value): value is string => Boolean(value));
    const cvss = asArray(vulnerability["cvss"]);
    const topScore = cvss
      .map((entry) => asRecord(entry))
      .map((entry) => Number(asRecord(entry?.["metrics"])?.["baseScore"]))
      .find((score) => Number.isFinite(score));
    const properties = asJsonValue({
      namespace: vulnerability["namespace"],
      dataSource: vulnerability["dataSource"],
      cvss: vulnerability["cvss"],
      matchDetails: match["matchDetails"],
    });

    findings.push(
      makeFinding({
        source: source("Grype", reportName, version),
        kind:
          sourceType?.includes("image") ||
          artifactType === "apk" ||
          artifactType === "deb" ||
          artifactType === "rpm"
            ? "container"
            : "sca",
        title: vulnerabilityId
          ? `${vulnerabilityId} in ${artifactName ?? "component"}`
          : `${artifactName ?? "Component"} vulnerability`,
        ...(asString(vulnerability["description"])
          ? { description: asString(vulnerability["description"]) }
          : {}),
        severity: normalizeSeverity(vulnerability["severity"] ?? topScore),
        identifiers: uniqueIdentifiers(identifiers),
        component: {
          ...(purl ? { purl } : {}),
          ...(artifactLanguage ? { ecosystem: artifactLanguage } : {}),
          ...(artifactName ? { name: artifactName } : {}),
          ...(artifactVersion ? { version: artifactVersion } : {}),
          ...(locationPath ? { path: locationPath } : {}),
          ...(artifactType ? { type: artifactType } : {}),
        },
        ...(targetAsset ? { asset: targetAsset } : {}),
        ...(locationPath ? { location: { uri: locationPath } } : {}),
        fingerprints: cleanStrings({ artifactId: asString(artifactRecord["id"]) }),
        remediation: {
          ...(fixedVersions.length > 0 ? { fixedVersion: fixedVersions.join(", ") } : {}),
          ...(asString(fix?.["state"])
            ? { recommendation: `Fix state: ${asString(fix?.["state"])}` }
            : {}),
        },
        references: [
          safeHttpReference(vulnerability["dataSource"]),
          ...asArray(vulnerability["urls"]).map(safeHttpReference),
          ...asArray(vulnerability["advisories"])
            .map((entry) => asRecord(entry)?.["link"])
            .map(safeHttpReference),
        ].filter((value): value is string => Boolean(value)),
        ...(properties && !Array.isArray(properties) && typeof properties === "object"
          ? { properties: properties as Record<string, JsonValue> }
          : {}),
        nativeId: `${matchIndex}:${vulnerabilityId ?? "finding"}:${asString(artifactRecord["id"]) ?? artifactName ?? "artifact"}`,
      }),
    );
  }

  return {
    format: "grype",
    sourceName: reportName,
    tool: "Grype",
    findings,
    warnings:
      findings.length === 0
        ? [{ code: "grype.no-findings", message: "No Grype matches were found." }]
        : [],
    metadata: {
      ...(target ? { target } : {}),
      ...(sourceType ? { sourceType } : {}),
    },
  };
}

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
import { asset, makeFinding, source } from "./common.js";

export function parseOsv(root: Record<string, unknown>, reportName: string): ParsedReport {
  const findings: CanonicalFinding[] = [];
  const results = asArray(root["results"]);

  for (const [resultIndex, resultValue] of results.entries()) {
    const result = asRecord(resultValue);
    if (!result) continue;
    const sourceRecord = asRecord(result["source"]);
    const sourcePath = asString(sourceRecord?.["path"]);
    const resultAsset = asset("file", sourcePath);
    for (const [packageIndex, packageValue] of asArray(result["packages"]).entries()) {
      const packageRecord = asRecord(packageValue);
      const packageInfo = asRecord(packageRecord?.["package"] ?? packageRecord);
      if (!packageRecord || !packageInfo) continue;
      const packageName = asString(packageInfo["name"]);
      const packageVersion = asString(packageInfo["version"]);
      const ecosystem = asString(packageInfo["ecosystem"]);
      const purl = asString(packageInfo["purl"]);
      for (const [vulnerabilityIndex, vulnerabilityValue] of asArray(
        packageRecord["vulnerabilities"],
      ).entries()) {
        const vulnerability = asRecord(vulnerabilityValue);
        if (!vulnerability) continue;
        const vulnerabilityId = asString(vulnerability["id"]);
        const aliases = asArray(vulnerability["aliases"])
          .map(asString)
          .filter((entry): entry is string => Boolean(entry));
        const identifiers: FindingIdentifier[] = extractIdentifiers(
          [
            vulnerabilityId,
            ...aliases,
            asString(vulnerability["summary"]),
            asString(vulnerability["details"]),
          ],
          "alias",
        );
        if (vulnerabilityId) {
          const identifier = normalizeIdentifier(vulnerabilityId, "primary");
          if (identifier) identifiers.push(identifier);
        }
        const databaseSpecific = asRecord(vulnerability["database_specific"]);
        const ecosystemSpecific = asRecord(vulnerability["ecosystem_specific"]);
        const severity = normalizeSeverity(
          databaseSpecific?.["severity"] ??
            ecosystemSpecific?.["severity"] ??
            cvssScore(vulnerability),
        );
        const fixedVersion = extractFixedVersion(vulnerability, packageName, ecosystem);
        const description = asString(vulnerability["details"]);
        const properties = asJsonValue({
          modified: vulnerability["modified"],
          published: vulnerability["published"],
          databaseSpecific: vulnerability["database_specific"],
          ecosystemSpecific: vulnerability["ecosystem_specific"],
          affected: vulnerability["affected"],
        });

        findings.push(
          makeFinding({
            source: source("OSV-Scanner", reportName),
            kind: "sca",
            title:
              asString(vulnerability["summary"]) ??
              vulnerabilityId ??
              `${packageName ?? "Package"} vulnerability`,
            ...(description ? { description } : {}),
            severity,
            identifiers: uniqueIdentifiers(identifiers),
            component: {
              ...(purl ? { purl } : {}),
              ...(ecosystem ? { ecosystem } : {}),
              ...(packageName ? { name: packageName } : {}),
              ...(packageVersion ? { version: packageVersion } : {}),
              ...(sourcePath ? { path: sourcePath } : {}),
            },
            ...(resultAsset ? { asset: resultAsset } : {}),
            ...(sourcePath ? { location: { uri: sourcePath } } : {}),
            remediation: {
              ...(fixedVersion ? { fixedVersion } : {}),
              ...(fixedVersion ? { recommendation: `Upgrade to ${fixedVersion} or later.` } : {}),
            },
            references: asArray(vulnerability["references"])
              .map((entry) => asRecord(entry)?.["url"])
              .map(safeHttpReference)
              .filter((entry): entry is string => Boolean(entry)),
            ...(properties && !Array.isArray(properties) && typeof properties === "object"
              ? { properties: properties as Record<string, JsonValue> }
              : {}),
            nativeId: `${resultIndex}:${packageIndex}:${vulnerabilityIndex}:${vulnerabilityId ?? "finding"}`,
          }),
        );
      }
    }
  }

  return {
    format: "osv-scanner",
    sourceName: reportName,
    tool: "OSV-Scanner",
    tools: ["OSV-Scanner"],
    findings,
    warnings:
      findings.length === 0
        ? [{ code: "osv.no-findings", message: "No OSV-Scanner findings were found." }]
        : [],
    metadata: { results: results.length },
  };
}

function cvssScore(vulnerability: Record<string, unknown>): string | undefined {
  const severity = asRecord(asArray(vulnerability["severity"])[0]);
  const score = asString(severity?.["score"]);
  if (!score) return undefined;
  const match = /CVSS:[^/]+\/.*?([0-9]+(?:\.[0-9]+)?)$/.exec(score);
  return match?.[1];
}

function extractFixedVersion(
  vulnerability: Record<string, unknown>,
  packageName: string | undefined,
  ecosystem: string | undefined,
): string | undefined {
  for (const affectedValue of asArray(vulnerability["affected"])) {
    const affected = asRecord(affectedValue);
    const affectedPackage = asRecord(affected?.["package"]);
    const sameName = !packageName || asString(affectedPackage?.["name"]) === packageName;
    const sameEcosystem = !ecosystem || asString(affectedPackage?.["ecosystem"]) === ecosystem;
    if (!sameName || !sameEcosystem) continue;
    const fixed = asArray(affected?.["ranges"])
      .flatMap((range) => asArray(asRecord(range)?.["events"]))
      .map((event) => asString(asRecord(event)?.["fixed"]))
      .filter((entry): entry is string => Boolean(entry));
    if (fixed.length > 0) return fixed.join(", ");
  }
  return undefined;
}

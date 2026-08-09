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

function packagePurl(
  ecosystem: string | undefined,
  name: string | undefined,
  version: string | undefined,
): string | undefined {
  if (!ecosystem || !name || !version) return undefined;
  const map: Record<string, string> = {
    npm: "npm",
    yarn: "npm",
    pip: "pypi",
    poetry: "pypi",
    maven: "maven",
    gradle: "maven",
    gomodules: "golang",
    nuget: "nuget",
    rubygems: "gem",
    composer: "composer",
    cocoapods: "cocoapods",
  };
  const type = map[ecosystem.toLowerCase()];
  return type
    ? `pkg:${type}/${encodeURIComponent(name)}@${encodeURIComponent(version)}`
    : undefined;
}

export function parseSnyk(root: Record<string, unknown>, reportName: string): ParsedReport {
  const findings: CanonicalFinding[] = [];
  const projectName = asString(root["projectName"] ?? root["displayTargetFile"] ?? root["path"]);
  const packageManagerRecord = asRecord(root["packageManager"]);
  const packageManager = asString(packageManagerRecord?.["name"] ?? root["packageManager"]);
  const targetFile = asString(root["displayTargetFile"]);
  const projectAsset = asset("repository", projectName);
  const vulnerabilities =
    asArray(root["vulnerabilities"]).length > 0
      ? asArray(root["vulnerabilities"])
      : asArray(asRecord(root["issues"])?.["vulnerabilities"]);

  for (const [index, value] of vulnerabilities.entries()) {
    const item = asRecord(value);
    if (!item) continue;
    const nativeId = asString(item["id"]);
    const identifierMap = asRecord(item["identifiers"]);
    const identifiers: FindingIdentifier[] = [];
    for (const [scheme, entries] of Object.entries(identifierMap ?? {})) {
      for (const candidate of asArray(entries).map(asString)) {
        if (!candidate) continue;
        const identifier = normalizeIdentifier(
          candidate,
          scheme.toUpperCase() === "CWE" ? "weakness" : "alias",
          scheme,
        );
        if (identifier) identifiers.push(identifier);
      }
    }
    identifiers.push(
      ...extractIdentifiers(
        [nativeId, asString(item["title"]), asString(item["description"])],
        "related",
      ),
    );
    if (nativeId) {
      const identifier = normalizeIdentifier(
        nativeId,
        "primary",
        nativeId.startsWith("SNYK-") ? "SNYK" : undefined,
      );
      if (identifier) identifiers.push(identifier);
    }
    const name = asString(item["packageName"] ?? item["name"]);
    const version = asString(item["version"]);
    const ecosystem = asString(item["packageManager"] ?? packageManager);
    const purl = asString(item["purl"]) ?? packagePurl(ecosystem, name, version);
    const from = asArray(item["from"])
      .map(asString)
      .filter((entry): entry is string => Boolean(entry));
    const path = from.length > 0 ? from.join(" > ") : targetFile;
    const fixedIn = asArray(item["fixedIn"])
      .map(asString)
      .filter((entry): entry is string => Boolean(entry));
    const recommendation = asString(item["remediation"]);
    const properties = asJsonValue({
      exploitMaturity: item["exploitMaturity"],
      publicationTime: item["publicationTime"],
      disclosureTime: item["disclosureTime"],
      isUpgradable: item["isUpgradable"],
      isPatchable: item["isPatchable"],
      upgradePath: item["upgradePath"],
    });

    findings.push(
      makeFinding({
        source: source("Snyk", reportName),
        kind: "sca",
        title: asString(item["title"]) ?? nativeId ?? `${name ?? "Package"} vulnerability`,
        ...(asString(item["description"]) ? { description: asString(item["description"]) } : {}),
        severity: normalizeSeverity(item["severity"] ?? item["cvssScore"]),
        identifiers: uniqueIdentifiers(identifiers),
        component: {
          ...(purl ? { purl } : {}),
          ...(ecosystem ? { ecosystem } : {}),
          ...(name ? { name } : {}),
          ...(version ? { version } : {}),
          ...(path ? { path } : {}),
        },
        ...(projectAsset ? { asset: projectAsset } : {}),
        ...(targetFile ? { location: { uri: targetFile } } : {}),
        fingerprints: cleanStrings({ snykId: nativeId }),
        remediation: {
          ...(fixedIn.length > 0 ? { fixedVersion: fixedIn.join(", ") } : {}),
          ...(recommendation ? { recommendation } : {}),
        },
        references: [
          safeHttpReference(item["url"]),
          ...asArray(item["references"])
            .map((entry) => asRecord(entry)?.["url"] ?? entry)
            .map(safeHttpReference),
        ].filter((entry): entry is string => Boolean(entry)),
        ...(properties && !Array.isArray(properties) && typeof properties === "object"
          ? { properties: properties as Record<string, JsonValue> }
          : {}),
        nativeId: `${index}:${nativeId ?? name ?? "finding"}`,
      }),
    );
  }

  return {
    format: "snyk",
    sourceName: reportName,
    tool: "Snyk",
    findings,
    warnings:
      findings.length === 0
        ? [{ code: "snyk.no-findings", message: "No Snyk vulnerabilities were found." }]
        : [],
    metadata: {
      ...(projectName ? { project: projectName } : {}),
      ...(packageManager ? { packageManager } : {}),
    },
  };
}

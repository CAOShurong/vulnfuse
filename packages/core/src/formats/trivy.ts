import { extractIdentifiers, normalizeIdentifier, uniqueIdentifiers } from "../identifiers.js";
import type {
  CanonicalFinding,
  FindingIdentifier,
  FindingKind,
  JsonValue,
  ParsedReport,
} from "../model.js";
import {
  asArray,
  asJsonValue,
  asRecord,
  asString,
  normalizeSeverity,
  safeHttpReference,
} from "../utils.js";
import { asset, cleanStrings, makeFinding, source } from "./common.js";

function kindFor(resultClass: string | undefined, resultType: string | undefined): FindingKind {
  const text = `${resultClass ?? ""} ${resultType ?? ""}`.toLowerCase();
  if (/secret/.test(text)) return "secret";
  if (/config|terraform|kubernetes|cloudformation|dockerfile/.test(text)) return "iac";
  if (/license/.test(text)) return "license";
  if (/os-pkgs|image|container/.test(text)) return "container";
  return "sca";
}

export function parseTrivy(root: Record<string, unknown>, reportName: string): ParsedReport {
  const findings: CanonicalFinding[] = [];
  const reportAsset = asString(root["ArtifactName"]);
  const artifactType = asString(root["ArtifactType"]);
  const trivy = asRecord(root["Trivy"]);
  const version = asString(trivy?.["Version"] ?? trivy?.["version"]);

  for (const [resultIndex, resultValue] of asArray(root["Results"]).entries()) {
    const result = asRecord(resultValue);
    if (!result) continue;
    const target = asString(result["Target"]);
    const resultClass = asString(result["Class"]);
    const resultType = asString(result["Type"]);
    const kind = kindFor(resultClass, resultType);
    const currentAsset = asset(
      kind === "container" || /image|container/i.test(artifactType ?? "")
        ? "image"
        : target
          ? "file"
          : "repository",
      reportAsset ?? target,
    );

    for (const [itemIndex, itemValue] of asArray(result["Vulnerabilities"]).entries()) {
      const item = asRecord(itemValue);
      if (!item) continue;
      const vulnerabilityId = asString(item["VulnerabilityID"]);
      const identifiers: FindingIdentifier[] = extractIdentifiers(
        [vulnerabilityId, asString(item["Title"]), asString(item["Description"])],
        "related",
      );
      if (vulnerabilityId) {
        const identifier = normalizeIdentifier(vulnerabilityId, "primary");
        if (identifier) identifiers.push(identifier);
      }
      const pkgName = asString(item["PkgName"]);
      const installedVersion = asString(item["InstalledVersion"]);
      const pkgPath = asString(item["PkgPath"]) ?? target;
      const fixedVersion = asString(item["FixedVersion"]);
      const purl = asString(
        item["PkgIdentifier"] ? asRecord(item["PkgIdentifier"])?.["PURL"] : undefined,
      );
      const references = [
        safeHttpReference(item["PrimaryURL"]),
        ...asArray(item["References"]).map(safeHttpReference),
      ].filter((value): value is string => Boolean(value));
      const properties = asJsonValue({
        status: item["Status"],
        cvss: item["CVSS"],
        dataSource: item["DataSource"],
      });
      findings.push(
        makeFinding({
          source: source("Trivy", reportName, version),
          kind,
          title:
            asString(item["Title"]) ?? vulnerabilityId ?? `${pkgName ?? "Package"} vulnerability`,
          ...(asString(item["Description"]) ? { description: asString(item["Description"]) } : {}),
          severity: normalizeSeverity(item["Severity"]),
          identifiers: uniqueIdentifiers(identifiers),
          component: {
            ...(purl ? { purl } : {}),
            ...(resultType ? { ecosystem: resultType } : {}),
            ...(pkgName ? { name: pkgName } : {}),
            ...(installedVersion ? { version: installedVersion } : {}),
            ...(pkgPath ? { path: pkgPath } : {}),
          },
          ...(currentAsset ? { asset: currentAsset } : {}),
          ...(target ? { location: { uri: target } } : {}),
          fingerprints: cleanStrings({
            trivyPkgId: asString(item["PkgID"]),
            layer: asString(asRecord(item["Layer"])?.["Digest"]),
          }),
          remediation: {
            ...(fixedVersion ? { fixedVersion } : {}),
            ...(asString(item["Status"])
              ? { recommendation: `Status: ${asString(item["Status"])}` }
              : {}),
          },
          references,
          ...(properties && !Array.isArray(properties) && typeof properties === "object"
            ? { properties: properties as Record<string, JsonValue> }
            : {}),
          nativeId: `${resultIndex}:${itemIndex}:${vulnerabilityId ?? pkgName ?? "finding"}`,
        }),
      );
    }

    for (const [itemIndex, itemValue] of asArray(result["Misconfigurations"]).entries()) {
      const item = asRecord(itemValue);
      if (!item) continue;
      const ruleId = asString(item["ID"]);
      const description = asString(item["Description"]);
      const identifiers = extractIdentifiers(
        [ruleId, asString(item["AVDID"]), asString(item["Title"]), asString(item["Description"])],
        "related",
      );
      findings.push(
        makeFinding({
          source: source("Trivy", reportName, version),
          kind: "iac",
          title: asString(item["Title"]) ?? ruleId ?? "Trivy misconfiguration",
          ...(description ? { description } : {}),
          severity: normalizeSeverity(item["Severity"]),
          identifiers,
          ...(currentAsset ? { asset: currentAsset } : {}),
          ...(target
            ? {
                component: { path: target },
                location: {
                  uri: target,
                  ...(asRecord(item["CauseMetadata"]) &&
                  asString(asRecord(item["CauseMetadata"])?.["StartLine"])
                    ? {
                        startLine: Number(asString(asRecord(item["CauseMetadata"])?.["StartLine"])),
                      }
                    : {}),
                },
              }
            : {}),
          ...(ruleId ? { ruleId } : {}),
          references: asArray(item["References"])
            .map(safeHttpReference)
            .filter((value): value is string => Boolean(value)),
          nativeId: `${resultIndex}:misconfig:${itemIndex}:${ruleId ?? "finding"}`,
        }),
      );
    }

    for (const [itemIndex, itemValue] of asArray(result["Secrets"]).entries()) {
      const item = asRecord(itemValue);
      if (!item) continue;
      const ruleId = asString(item["RuleID"]);
      findings.push(
        makeFinding({
          source: source("Trivy", reportName, version),
          kind: "secret",
          title: asString(item["Title"]) ?? ruleId ?? "Potential secret",
          severity: normalizeSeverity(item["Severity"] ?? "high"),
          ...(currentAsset ? { asset: currentAsset } : {}),
          ...(target
            ? {
                component: { path: target },
                location: {
                  uri: target,
                  ...(Number.isFinite(Number(item["StartLine"]))
                    ? { startLine: Number(item["StartLine"]) }
                    : {}),
                  ...(Number.isFinite(Number(item["EndLine"]))
                    ? { endLine: Number(item["EndLine"]) }
                    : {}),
                },
              }
            : {}),
          ...(ruleId ? { ruleId } : {}),
          fingerprints: cleanStrings({
            match: asString(item["Match"]),
            category: asString(item["Category"]),
          }),
          nativeId: `${resultIndex}:secret:${itemIndex}:${ruleId ?? "finding"}`,
        }),
      );
    }
  }

  return {
    format: "trivy",
    sourceName: reportName,
    tool: "Trivy",
    tools: ["Trivy"],
    toolVersions: version ? { Trivy: [version] } : {},
    findings,
    warnings:
      findings.length === 0
        ? [{ code: "trivy.no-findings", message: "No supported Trivy findings were found." }]
        : [],
    metadata: {
      schemaVersion: asString(root["SchemaVersion"]) ?? "unknown",
      ...(reportAsset ? { artifact: reportAsset } : {}),
      ...(artifactType ? { artifactType } : {}),
      ...(asString(root["CreatedAt"]) ? { createdAt: asString(root["CreatedAt"]) as string } : {}),
    },
  };
}

import type { CorrelationResult, FindingCluster } from "../model.js";

export function exportSarif(result: CorrelationResult): string {
  const document = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "VulnFuse",
            semanticVersion: "0.3.0",
            informationUri: "https://github.com/CAOShurong/vulnfuse",
            rules: result.clusters.map((cluster) => ruleFor(cluster)),
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            properties: { summary: result.summary, correlationOptions: result.options },
          },
        ],
        results: result.clusters.map((cluster) => resultFor(cluster)),
      },
    ],
  };
  return `${JSON.stringify(document, null, 2)}\n`;
}

function ruleFor(cluster: FindingCluster): Record<string, unknown> {
  return {
    id: cluster.id,
    name: cluster.identifiers[0]?.value ?? cluster.id,
    shortDescription: { text: cluster.primary.title },
    ...(cluster.primary.description
      ? { fullDescription: { text: cluster.primary.description } }
      : {}),
    ...(cluster.primary.references[0] ? { helpUri: cluster.primary.references[0] } : {}),
    properties: {
      tags: [
        "security",
        cluster.primary.kind,
        ...cluster.identifiers.map((identifier) => identifier.value),
      ],
      "security-severity": securityScore(cluster.severity),
    },
  };
}

function resultFor(cluster: FindingCluster): Record<string, unknown> {
  const location = cluster.primary.location;
  return {
    ruleId: cluster.id,
    level: sarifLevel(cluster.severity),
    message: {
      text: `${cluster.primary.title} (${cluster.members.length} source record${cluster.members.length === 1 ? "" : "s"}: ${cluster.sourceTools.join(", ")})`,
    },
    fingerprints: { vulnfuseClusterId: cluster.id },
    partialFingerprints: { primaryLocationLineHash: cluster.id },
    ...(location?.uri
      ? {
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: location.uri },
                ...(location.startLine
                  ? {
                      region: {
                        startLine: location.startLine,
                        ...(location.endLine ? { endLine: location.endLine } : {}),
                        ...(location.startColumn ? { startColumn: location.startColumn } : {}),
                      },
                    }
                  : {}),
              },
            },
          ],
        }
      : {}),
    properties: {
      sourceTools: cluster.sourceTools,
      sourceFindingIds: cluster.members.map((member) => member.id),
      matchConfidence: cluster.confidence,
      identifiers: cluster.identifiers,
      assets: cluster.assets,
    },
  };
}

function sarifLevel(severity: FindingCluster["severity"]): "error" | "warning" | "note" | "none" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  if (severity === "low" || severity === "info") return "note";
  return "none";
}

function securityScore(severity: FindingCluster["severity"]): string {
  return { critical: "9.5", high: "8.0", medium: "5.5", low: "2.0", info: "0.1", unknown: "0.0" }[
    severity
  ];
}

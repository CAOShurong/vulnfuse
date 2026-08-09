import Papa from "papaparse";

import type { CorrelationResult } from "../model.js";

export function exportCsv(result: CorrelationResult): string {
  const rows = result.clusters.map((cluster) => ({
    cluster_id: cluster.id,
    severity: cluster.severity,
    kind: cluster.primary.kind,
    title: cluster.primary.title,
    identifiers: cluster.identifiers.map((identifier) => identifier.value).join(";"),
    purl: cluster.primary.component?.purl ?? "",
    component: cluster.primary.component?.name ?? "",
    component_version: cluster.primary.component?.version ?? "",
    assets: cluster.assets.map((item) => item.name).join(";"),
    source_tools: cluster.sourceTools.join(";"),
    source_records: cluster.members.length,
    duplicates_collapsed: Math.max(0, cluster.members.length - 1),
    confidence: cluster.confidence,
    fixed_version: cluster.primary.remediation?.fixedVersion ?? "",
    references: cluster.primary.references.join(";"),
  }));
  return `${Papa.unparse(rows, { newline: "\n", escapeFormulae: true })}\n`;
}

import type {
  BaselineDiffResult,
  BaselineState,
  ClusterEdge,
  CorrelationOptions,
  CorrelationResult,
  CoverageSummary,
  FindingCluster,
  MatchBlocker,
  MatchExplanation,
  MatchReason,
  Severity,
} from "../model.js";
import { clusterDisposition } from "../model.js";
import { describeScanSetChange } from "../compare.js";

interface PortableItem {
  cluster: FindingCluster;
  state?: BaselineState;
  changedFields: string[];
  baselineExplanation?: MatchExplanation;
  blockers: MatchBlocker[];
}

interface PortableReport {
  title: string;
  eyebrow: string;
  summary: string;
  options: CorrelationOptions;
  items: PortableItem[];
  stats: Array<{ label: string; value: number; note: string }>;
  severityCounts: Record<Severity, number>;
  coverage: CoverageSummary;
  stateCounts?: Record<BaselineState, number>;
  scanSetWarning?: string;
}

export function exportHtml(result: CorrelationResult): string {
  return renderPortableReport({
    title: "VulnFuse correlation report",
    eyebrow: "Explainable cross-scanner correlation",
    summary: `${result.summary.inputFindings} source records became ${result.summary.clusters} clusters: ${result.summary.activeClusters} active, ${result.summary.suppressedClusters} effectively suppressed, and ${result.summary.nonFindingClusters} non-finding; ${result.summary.duplicatesCollapsed} duplicate records were collapsed without discarding their evidence.`,
    options: result.options,
    items: result.clusters.map((cluster) => ({
      cluster,
      changedFields: [],
      blockers: blockersForCluster(cluster, result.rejectedCandidates),
    })),
    stats: [
      {
        label: "Source findings",
        value: result.summary.inputFindings,
        note: `from ${result.summary.sourceTools.length} tool${result.summary.sourceTools.length === 1 ? "" : "s"}`,
      },
      {
        label: "Clusters",
        value: result.summary.clusters,
        note: `${result.summary.activeClusters} active; ${result.summary.suppressedClusters} suppressed; ${result.summary.nonFindingClusters} non-finding`,
      },
      {
        label: "Collapsed",
        value: result.summary.duplicatesCollapsed,
        note: "source records retained",
      },
      { label: "Reports", value: result.summary.inputReports, note: "processed locally" },
    ],
    severityCounts: result.summary.bySeverity,
    coverage: result.summary.coverage,
  });
}

export function exportBaselineHtml(result: BaselineDiffResult): string {
  const severityCounts = zeroSeverityCounts();
  for (const item of result.items) severityCounts[item.cluster.severity] += 1;
  return renderPortableReport({
    title: "VulnFuse baseline comparison",
    eyebrow: "Explainable change review",
    summary: `Compared ${result.summary.currentClusters} current clusters with ${result.summary.baselineClusters} baseline clusters: ${result.summary.new} new, ${result.summary.updated} updated, ${result.summary.absent} absent, and ${result.summary.unchanged} unchanged.`,
    options: result.options,
    items: result.items.map((item) => ({
      cluster: item.cluster,
      state: item.state,
      changedFields: item.changedFields,
      ...(item.explanation ? { baselineExplanation: item.explanation } : {}),
      blockers: [],
    })),
    stats: [
      { label: "New", value: result.summary.new, note: "not present before" },
      { label: "Updated", value: result.summary.updated, note: "evidence changed" },
      { label: "Absent", value: result.summary.absent, note: "not observed now" },
      { label: "Unchanged", value: result.summary.unchanged, note: "stable match" },
    ],
    severityCounts,
    coverage: result.currentSummary.coverage,
    stateCounts: {
      new: result.summary.new,
      updated: result.summary.updated,
      absent: result.summary.absent,
      unchanged: result.summary.unchanged,
    },
    ...(result.scanSetChange.detected
      ? { scanSetWarning: describeScanSetChange(result.scanSetChange) }
      : {}),
  });
}

function renderPortableReport(report: PortableReport): string {
  const activeCount = report.items.filter(
    (item) => clusterDisposition(item.cluster) === "active",
  ).length;
  const suppressedCount = report.items.filter(
    (item) => clusterDisposition(item.cluster) === "suppressed",
  ).length;
  const nonFindingCount = report.items.filter(
    (item) => clusterDisposition(item.cluster) === "non-finding",
  ).length;
  const assetNames = uniqueSorted(
    report.items.flatMap((item) => item.cluster.assets.map((asset) => asset.name)),
  );
  const assetIds = new Map(assetNames.map((name, index) => [name, `asset-${index + 1}`]));
  const toolNames = uniqueSorted(report.items.flatMap((item) => item.cluster.sourceTools));
  const toolIds = new Map(toolNames.map((name, index) => [name, `tool-${index + 1}`]));
  const stateFilter = report.stateCounts
    ? `<label>State<select id="state-filter"><option value="all">All states</option>${(
        ["new", "updated", "absent", "unchanged"] as BaselineState[]
      )
        .map(
          (state) =>
            `<option value="${state}">${capitalize(state)} (${report.stateCounts?.[state] ?? 0})</option>`,
        )
        .join("")}</select></label>`
    : "";
  const assetFilter =
    assetNames.length > 0
      ? `<label>Asset<select id="asset-filter"><option value="all">All assets</option>${assetNames
          .map((name) => `<option value="${assetIds.get(name)}">${escapeHtml(name)}</option>`)
          .join("")}</select></label>`
      : "";
  const toolFilter =
    toolNames.length > 1
      ? `<label>Scanner<select id="tool-filter"><option value="all">All scanners</option>${toolNames
          .map((name) => `<option value="${toolIds.get(name)}">${escapeHtml(name)}</option>`)
          .join("")}</select></label>`
      : "";
  const items = report.items
    .map((item, index) => renderFinding(item, assetIds, toolIds, index === 0))
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
  <meta name="generator" content="VulnFuse 0.4.24">
  <title>${escapeHtml(report.title)}</title>
  <style>${portableStyles}${coverageStyles}</style>
</head>
<body>
  <header class="hero">
    <div class="brand"><span class="brand-mark">VF</span><span>VulnFuse</span><span class="version">portable report · 0.4</span></div>
    <div class="hero-copy">
      <p class="eyebrow">${escapeHtml(report.eyebrow)}</p>
      <h1>${escapeHtml(report.title)}</h1>
      <p class="lede">${escapeHtml(report.summary)}</p>
      <p class="policy">Threshold ${report.options.threshold} · ${escapeHtml(report.options.scope)} scope · line window ${report.options.lineWindow} · title weight ${report.options.titleWeight}</p>
    </div>
  </header>
  <main>
    <section class="stats" aria-label="Report summary">
      ${report.stats.map(renderStat).join("\n      ")}
    </section>
    <section class="severity-panel" aria-label="Severity distribution">
      <div><span>Severity distribution</span><strong>${report.items.length} clusters</strong></div>
      <div class="severity-bar">${renderSeverityBar(report.severityCounts)}</div>
      <div class="severity-legend">${renderSeverityLegend(report.severityCounts)}</div>
    </section>
    ${renderCoverage(report.coverage, Boolean(report.stateCounts))}
    <section class="controls" aria-label="Report filters">
      <label class="search-label">Search<input id="search" type="search" placeholder="CVE, package, asset, report…" autocomplete="off"></label>
      <label>Severity<select id="severity-filter"><option value="all">All severities</option>${[
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "unknown",
      ]
        .map(
          (severity) =>
            `<option value="${severity}">${capitalize(severity)} (${report.severityCounts[severity as Severity]})</option>`,
        )
        .join("")}</select></label>
      ${stateFilter}
      ${assetFilter}
      ${toolFilter}
      <label>Coverage<select id="coverage-filter"><option value="all">All evidence</option><option value="multi">Multiple scanners</option><option value="single">One scanner only</option></select></label>
      <label>Disposition<select id="disposition-filter"><option value="all">All dispositions</option><option value="active">Active (${activeCount})</option><option value="suppressed">Effectively suppressed (${suppressedCount})</option><option value="non-finding">Non-finding evidence (${nonFindingCount})</option></select></label>
      <div class="view-actions"><button id="expand-all" type="button">Expand all</button><button id="collapse-all" type="button">Collapse all</button></div>
    </section>
    <div class="result-line"><strong id="result-count">${report.items.length}</strong> of ${report.items.length} clusters shown</div>
    <noscript><p class="notice">JavaScript is disabled. Every finding remains readable, but search and filters are unavailable.</p></noscript>
    <section id="findings" class="findings" aria-label="Correlated vulnerability clusters">
      ${items || '<p class="empty">No vulnerability clusters were produced.</p>'}
    </section>
    ${report.stateCounts ? '<p class="notice"><strong>Important:</strong> absent means a cluster was not observed in the current inputs. It is not proof of remediation.</p>' : ""}
    ${report.scanSetWarning ? `<p class="notice"><strong>Scan set changed:</strong> ${escapeHtml(report.scanSetWarning.replace(/^Scan set changed:\s*/, ""))}</p>` : ""}
  </main>
  <footer>
    <strong>VulnFuse</strong>
    <span>This self-contained file makes no network requests. It may contain sensitive paths, assets, packages, and evidence; protect it like the original scanner reports.</span>
  </footer>
  <script>${portableScript}</script>
</body>
</html>
`;
}

function renderCoverage(coverage: CoverageSummary, currentOnly: boolean): string {
  const pairwise = coverage.pairwiseOmitted
    ? '<p class="coverage-note">Pairwise rows are omitted when more than 20 tools are present to keep the report bounded.</p>'
    : coverage.pairs.length > 0
      ? `<div class="coverage-table-wrap"><table><caption>Pairwise overlap</caption><thead><tr><th>Tool pair</th><th>Shared</th><th>Union</th><th>Jaccard</th></tr></thead><tbody>${coverage.pairs
          .map(
            (pair) =>
              `<tr><td>${escapeHtml(pair.leftTool)} / ${escapeHtml(pair.rightTool)}</td><td>${pair.sharedClusters}</td><td>${pair.unionClusters}</td><td>${formatPercent(pair.overlapRatio)}</td></tr>`,
          )
          .join("")}</tbody></table></div>`
      : '<p class="coverage-note">Add a second scanner to measure cross-tool overlap.</p>';
  return `<section class="coverage-panel" aria-label="Scanner coverage">
    <div class="coverage-head"><div><span>Scanner divergence</span><h2>What each tool actually reported</h2></div><div class="coverage-totals"><strong>${coverage.singleToolClusters}</strong><span>one-tool clusters</span><strong>${coverage.multiToolClusters}</strong><span>multi-tool clusters</span></div></div>
    <p class="coverage-note">${currentOnly ? "Coverage below describes current-run clusters; absent baseline clusters are excluded. " : ""}A one-tool finding is a review lead, not proof that the tool is right or wrong.</p>
    <div class="coverage-tables">
      <div class="coverage-table-wrap"><table><caption>Per-tool coverage</caption><thead><tr><th>Tool</th><th>Reports</th><th>Findings</th><th>Clusters</th><th>Only tool</th><th>Shared</th></tr></thead><tbody>${coverage.tools
        .map(
          (tool) =>
            `<tr><td>${escapeHtml(tool.tool)}</td><td>${tool.reports}</td><td>${tool.sourceFindings}</td><td>${tool.clusters}</td><td>${tool.exclusiveClusters}</td><td>${tool.sharedClusters}</td></tr>`,
        )
        .join("")}</tbody></table></div>
      ${pairwise}
    </div>
  </section>`;
}

function renderStat(stat: PortableReport["stats"][number]): string {
  return `<article><span>${escapeHtml(stat.label)}</span><strong>${stat.value}</strong><small>${escapeHtml(stat.note)}</small></article>`;
}

function formatPercent(ratio: number): string {
  return `${(ratio * 100).toFixed(1)}%`;
}

function renderFinding(
  item: PortableItem,
  assetIds: Map<string, string>,
  toolIds: Map<string, string>,
  initiallyOpen: boolean,
): string {
  const cluster = item.cluster;
  const identifiers = cluster.identifiers.map((identifier) => identifier.value);
  const component = componentLabel(cluster);
  const assets = cluster.assets.map((asset) => asset.name);
  const searchText = normalizeSearchText([
    cluster.id,
    cluster.primary.title,
    cluster.primary.description,
    component,
    ...identifiers,
    ...assets,
    ...cluster.sourceTools,
    ...cluster.members.flatMap((member) => [
      member.source.tool,
      member.source.report,
      member.title,
      member.ruleId,
      member.location?.uri,
      ...(member.suppressions ?? []).flatMap((suppression) => [
        suppression.kind,
        suppression.status,
        suppression.justification,
      ]),
    ]),
  ]);
  const assetTokens = assets
    .map((asset) => assetIds.get(asset))
    .filter((value): value is string => Boolean(value))
    .join(" ");
  const toolTokens = cluster.sourceTools
    .map((tool) => toolIds.get(tool))
    .filter((value): value is string => Boolean(value))
    .join(" ");
  const coverage = cluster.sourceTools.length > 1 ? "multi" : "single";
  const disposition = clusterDisposition(cluster);
  const state = item.state ?? "correlated";
  const stateBadge = item.state
    ? `<span class="state ${item.state}">${escapeHtml(item.state)}</span>`
    : `<span class="confidence">${escapeHtml(cluster.confidence)} confidence</span>`;
  const dispositionBadge =
    disposition === "non-finding"
      ? '<span class="suppression non-finding">non-finding evidence</span>'
      : disposition === "suppressed"
        ? '<span class="suppression suppressed">effectively suppressed</span>'
        : '<span class="suppression active">active</span>';
  const description = cluster.primary.description
    ? `<p class="description">${escapeHtml(cluster.primary.description)}</p>`
    : "";
  const baseline = item.state ? renderBaseline(item) : "";
  const reasons = uniqueReasons(cluster.edges.flatMap((edge) => edge.explanation.reasons));
  const referenceLinks = uniqueSorted(cluster.members.flatMap((member) => member.references))
    .map(safeReference)
    .filter((value): value is string => Boolean(value))
    .map(
      (reference) =>
        `<a href="${escapeHtml(reference)}" target="_blank" rel="noopener noreferrer">${escapeHtml(reference)}</a>`,
    )
    .join("");
  return `<details class="finding" data-search="${escapeHtml(searchText)}" data-severity="${cluster.severity}" data-state="${state}" data-assets="${assetTokens}" data-tools="${toolTokens}" data-coverage="${coverage}" data-disposition="${disposition}"${initiallyOpen ? " open" : ""}>
  <summary>
    <span class="severity ${cluster.severity}">${cluster.severity}</span>
    <span class="summary-copy"><strong>${escapeHtml(cluster.primary.title)}</strong><small>${escapeHtml(identifiers[0] ?? cluster.id)} · ${escapeHtml(component)} · ${escapeHtml(assets.join(", ") || "unknown asset")}</small></span>
    <span class="badges">${stateBadge}${dispositionBadge}</span>
    <span class="record-count">${cluster.members.length} record${cluster.members.length === 1 ? "" : "s"}</span>
  </summary>
  <div class="finding-body">
    ${baseline}
    ${description}
    <dl class="facts">
      ${fact("Cluster", cluster.id, true)}
      ${fact("Identifiers", identifiers.join(", ") || "none")}
      ${fact("Component", component, true)}
      ${fact("Assets", cluster.assets.map((asset) => `${asset.type}: ${asset.name}`).join(", ") || "unknown")}
      ${fact("Sources", `${cluster.sourceTools.join(", ")} (${cluster.members.length} record${cluster.members.length === 1 ? "" : "s"})`)}
      ${fact("Disposition", dispositionLabel(cluster))}
      ${fact("Remediation", remediationLabel(cluster))}
    </dl>
    ${renderReasons(reasons)}
    ${renderBlockers(item.blockers)}
    ${renderMembers(cluster)}
    ${referenceLinks ? `<section class="evidence"><div class="section-head"><h2>References</h2><span>${referenceLinks.match(/<a /g)?.length ?? 0}</span></div><div class="references">${referenceLinks}</div></section>` : ""}
  </div>
</details>`;
}

function renderBaseline(item: PortableItem): string {
  if (!item.state) return "";
  let message: string;
  if (item.state === "new") message = "No matching baseline cluster was found.";
  else if (item.state === "absent")
    message = "This baseline cluster was not observed in the current reports.";
  else {
    const score = item.baselineExplanation?.score ?? 100;
    const confidence = item.baselineExplanation?.confidence ?? "exact";
    message = `Matched the baseline at ${score}/100 (${confidence} confidence).`;
  }
  const changed =
    item.changedFields.length > 0
      ? `<span>Changed fields: ${escapeHtml(item.changedFields.join(", "))}</span>`
      : "";
  return `<div class="baseline-callout ${item.state}"><strong>${capitalize(item.state)}</strong><span>${escapeHtml(message)}</span>${changed}</div>`;
}

function renderReasons(reasons: MatchReason[]): string {
  if (reasons.length === 0) {
    return '<section class="evidence"><div class="section-head"><h2>Correlation evidence</h2><span>single record</span></div><p class="muted">A single source record needs no merge claim.</p></section>';
  }
  return `<section class="evidence"><div class="section-head"><h2>Why these records merged</h2><span>${reasons.length} reason${reasons.length === 1 ? "" : "s"}</span></div><div class="reason-list">${reasons
    .map(
      (reason) =>
        `<article><b>+${reason.score}</b><div><strong>${escapeHtml(reason.feature)}</strong><p>${escapeHtml(reason.message)}</p>${reason.evidence?.length ? `<small>${escapeHtml(reason.evidence.join(" · "))}</small>` : ""}</div></article>`,
    )
    .join("")}</div></section>`;
}

function renderBlockers(blockers: MatchBlocker[]): string {
  if (blockers.length === 0) return "";
  return `<section class="evidence"><div class="section-head"><h2>Why nearby candidates stayed separate</h2><span>${blockers.length} blocker${blockers.length === 1 ? "" : "s"}</span></div><div class="blocker-list">${blockers
    .map(
      (blocker) =>
        `<article><b>×</b><div><strong>${escapeHtml(blocker.feature)}</strong><p>${escapeHtml(blocker.message)}</p></div></article>`,
    )
    .join("")}</div></section>`;
}

function renderMembers(cluster: FindingCluster): string {
  return `<section class="evidence"><div class="section-head"><h2>Source records</h2><span>${cluster.members.length}</span></div><div class="member-list">${cluster.members
    .map((member) => {
      const identifiers = member.identifiers.map((identifier) => identifier.value).join(", ");
      const location = locationLabel(member.location);
      const component =
        member.component?.purl ??
        [member.component?.name, member.component?.version].filter(Boolean).join("@");
      const suppressionDetails = (member.suppressions ?? [])
        .map(
          (suppression) =>
            `<li><strong>${escapeHtml(suppression.kind)}</strong> · ${escapeHtml(suppression.status ?? "status omitted")}${suppression.justification ? `<p>${escapeHtml(suppression.justification)}</p>` : ""}</li>`,
        )
        .join("");
      const memberSuppression = suppressionDetails
        ? `<div class="suppression-evidence"><span>${member.suppressed ? "Effectively suppressed" : "Suppression contested"}</span><ul>${suppressionDetails}</ul></div>`
        : "";
      const resultKind = member.properties["sarif.resultKind"];
      const resultKindFact =
        typeof resultKind === "string" || typeof resultKind === "number"
          ? fact(
              "SARIF result",
              `${String(resultKind)}${member.nonFinding ? " (non-finding evidence)" : ""}`,
            )
          : "";
      return `<article class="member"><div class="member-head"><span class="tool">${escapeHtml(member.source.tool.slice(0, 2).toUpperCase())}</span><div><strong>${escapeHtml(member.source.tool)}</strong><small>${escapeHtml(member.source.report)}</small></div><span class="mini-severity ${member.severity}">${member.severity}</span></div><dl>${fact("Finding", member.title)}${resultKindFact}${fact("Identifier", identifiers || "none")}${fact("Component", component || "unknown", true)}${fact("Location", location || "not supplied", true)}</dl>${memberSuppression}</article>`;
    })
    .join("")}</div></section>`;
}

function dispositionLabel(cluster: FindingCluster): string {
  const disposition = clusterDisposition(cluster);
  if (disposition === "non-finding") return "non-finding evidence";
  if (disposition === "suppressed") return "effectively suppressed";
  return "active";
}

function fact(label: string, value: string, mono = false): string {
  return `<div><dt>${escapeHtml(label)}</dt><dd${mono ? ' class="mono"' : ""}>${escapeHtml(value)}</dd></div>`;
}

function componentLabel(cluster: FindingCluster): string {
  const namedComponent = [cluster.primary.component?.name, cluster.primary.component?.version]
    .filter(Boolean)
    .join("@");
  return cluster.primary.component?.purl || namedComponent || "unknown";
}

function remediationLabel(cluster: FindingCluster): string {
  return (
    cluster.primary.remediation?.fixedVersion ??
    cluster.primary.remediation?.recommendation ??
    "not supplied"
  );
}

function locationLabel(location: FindingCluster["primary"]["location"]): string {
  if (!location) return "";
  const line = location.startLine ? `:${location.startLine}` : "";
  const column = location.startColumn ? `:${location.startColumn}` : "";
  return `${location.uri ?? "unknown"}${line}${column}`;
}

function blockersForCluster(cluster: FindingCluster, rejected: ClusterEdge[]): MatchBlocker[] {
  const memberIds = new Set(cluster.members.map((member) => member.id));
  const blockers = rejected
    .filter((edge) => memberIds.has(edge.leftId) || memberIds.has(edge.rightId))
    .flatMap((edge) => edge.explanation.blockers);
  return [
    ...new Map(
      blockers.map((blocker) => [`${blocker.feature}:${blocker.message}`, blocker]),
    ).values(),
  ];
}

function uniqueReasons(reasons: MatchReason[]): MatchReason[] {
  return [
    ...new Map(
      reasons.map((reason) => [
        `${reason.feature}:${reason.score}:${reason.message}:${reason.evidence?.join("|") ?? ""}`,
        reason,
      ]),
    ).values(),
  ];
}

function renderSeverityBar(counts: Record<Severity, number>): string {
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0) || 1;
  return (["critical", "high", "medium", "low", "info", "unknown"] as Severity[])
    .filter((severity) => counts[severity] > 0)
    .map(
      (severity) =>
        `<span class="${severity}" style="width:${(counts[severity] / total) * 100}%" title="${severity}: ${counts[severity]}"></span>`,
    )
    .join("");
}

function renderSeverityLegend(counts: Record<Severity, number>): string {
  return (["critical", "high", "medium", "low", "info", "unknown"] as Severity[])
    .map(
      (severity) =>
        `<span><i class="${severity}"></i>${capitalize(severity)} <b>${counts[severity]}</b></span>`,
    )
    .join("");
}

function safeReference(value: string): string | undefined {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? url.toString() : undefined;
  } catch {
    return undefined;
  }
}

function normalizeSearchText(values: Array<string | undefined>): string {
  return values
    .filter((value): value is string => Boolean(value))
    .join(" ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function uniqueSorted(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function capitalize(value: string): string {
  return `${value.slice(0, 1).toUpperCase()}${value.slice(1)}`;
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ??
      character,
  );
}

function zeroSeverityCounts(): Record<Severity, number> {
  return { unknown: 0, info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

const portableScript = String.raw`(() => {
  const search = document.getElementById("search");
  const severity = document.getElementById("severity-filter");
  const state = document.getElementById("state-filter");
  const asset = document.getElementById("asset-filter");
  const tool = document.getElementById("tool-filter");
  const coverage = document.getElementById("coverage-filter");
  const disposition = document.getElementById("disposition-filter");
  const count = document.getElementById("result-count");
  const findings = Array.from(document.querySelectorAll(".finding"));

  function applyFilters() {
    const query = (search?.value || "").trim().toLowerCase();
    const selectedSeverity = severity?.value || "all";
    const selectedState = state?.value || "all";
    const selectedAsset = asset?.value || "all";
    const selectedTool = tool?.value || "all";
    const selectedCoverage = coverage?.value || "all";
    const selectedDisposition = disposition?.value || "all";
    let visible = 0;
    for (const finding of findings) {
      const matchesQuery = !query || (finding.dataset.search || "").includes(query);
      const matchesSeverity =
        selectedSeverity === "all" || finding.dataset.severity === selectedSeverity;
      const matchesState = selectedState === "all" || finding.dataset.state === selectedState;
      const matchesAsset =
        selectedAsset === "all" ||
        (finding.dataset.assets || "").split(" ").includes(selectedAsset);
      const matchesTool =
        selectedTool === "all" ||
        (finding.dataset.tools || "").split(" ").includes(selectedTool);
      const matchesCoverage =
        selectedCoverage === "all" || finding.dataset.coverage === selectedCoverage;
      const matchesDisposition =
        selectedDisposition === "all" || finding.dataset.disposition === selectedDisposition;
      finding.hidden = !(
        matchesQuery &&
        matchesSeverity &&
        matchesState &&
        matchesAsset &&
        matchesTool &&
        matchesCoverage &&
        matchesDisposition
      );
      if (!finding.hidden) visible += 1;
    }
    count.textContent = String(visible);
  }

  for (const control of [search, severity, state, asset, tool, coverage, disposition]) {
    control?.addEventListener(control === search ? "input" : "change", applyFilters);
  }
  document.getElementById("expand-all")?.addEventListener("click", () => {
    for (const finding of findings) if (!finding.hidden) finding.open = true;
  });
  document.getElementById("collapse-all")?.addEventListener("click", () => {
    for (const finding of findings) finding.open = false;
  });
})();`;

const coverageStyles = String.raw`
.coverage-panel{margin-top:12px;padding:18px;border:1px solid var(--line);background:rgba(11,24,21,.9);border-radius:16px}.coverage-head{display:flex;justify-content:space-between;gap:24px}.coverage-head>div:first-child>span{color:var(--mint);font-size:10px;font-weight:850;text-transform:uppercase;letter-spacing:.1em}.coverage-head h2{font-size:20px;margin:3px 0}.coverage-totals{display:grid;grid-template-columns:auto auto;align-items:baseline;gap:1px 8px}.coverage-totals strong{font-size:20px;color:var(--mint);text-align:right}.coverage-totals span,.coverage-note{color:var(--muted);font-size:11px}.coverage-note{margin:8px 0 0}.coverage-tables{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(0,1fr);gap:12px;margin-top:14px}.coverage-table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px}.coverage-table-wrap table{width:100%;border-collapse:collapse;font-size:11px}.coverage-table-wrap caption{text-align:left;padding:9px 10px;color:var(--muted);font-weight:750}.coverage-table-wrap th,.coverage-table-wrap td{padding:8px 10px;border-top:1px solid var(--line);text-align:right;white-space:nowrap}.coverage-table-wrap th:first-child,.coverage-table-wrap td:first-child{text-align:left}.coverage-table-wrap th{color:var(--muted);font-size:9px;text-transform:uppercase;letter-spacing:.05em}@media(max-width:800px){.coverage-head{display:block}.coverage-totals{justify-content:start;margin-top:10px}.coverage-totals strong{text-align:left}.coverage-tables{grid-template-columns:1fr}}
`;

const portableStyles =
  String.raw`
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#eef8f3;background:#07110f;--ink:#eef8f3;--muted:#8da49b;--line:rgba(177,218,198,.16);--panel:#0b1815;--panel2:#10221d;--mint:#8cf6c3;--mint2:#37e39b;--critical:#ff5f78;--high:#ff936b;--medium:#ffc86b;--low:#7bd9ff;--info:#91a8ff;--unknown:#687b74}*{box-sizing:border-box}body{margin:0;min-width:320px;background:radial-gradient(circle at 78% 0,rgba(55,227,155,.09),transparent 34rem),#07110f;line-height:1.5}.hero,main,footer{width:min(1180px,calc(100% - 40px));margin:auto}.hero{padding:34px 0 48px;border-bottom:1px solid var(--line)}.brand{display:flex;gap:11px;align-items:center;font-weight:800}.brand-mark{display:grid;place-items:center;width:32px;height:32px;border:1px solid rgba(140,246,195,.55);border-radius:10px;color:var(--mint);font-size:12px;background:rgba(55,227,155,.08)}.version{font-size:12px;color:var(--muted);font-weight:650}.hero-copy{max-width:850px;padding-top:52px}.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:12px;color:var(--mint);font-weight:800}.hero h1{font-size:clamp(38px,6vw,72px);line-height:1.02;letter-spacing:-.055em;margin:12px 0 20px}.lede{font-size:clamp(17px,2vw,22px);color:#b9cec5;max-width:800px}.policy{font:12px ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted);margin-top:22px}main{padding:36px 0 60px}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.stats article,.severity-panel,.controls,.finding,.notice{border:1px solid var(--line);background:rgba(11,24,21,.9);border-radius:16px}.stats article{padding:18px}.stats span,.stats small{display:block;color:var(--muted);font-size:12px}.stats strong{display:block;font-size:32px;color:var(--mint);line-height:1.15;margin:7px 0}.severity-panel{margin-top:12px;padding:18px}.severity-panel>div:first-child{display:flex;justify-content:space-between;gap:16px}.severity-panel span{color:var(--muted)}.severity-bar{height:9px;display:flex;overflow:hidden;border-radius:99px;background:#14221f;margin:14px 0}.severity-bar span{display:block}.critical{background-color:var(--critical)}.high{background-color:var(--high)}.medium{background-color:var(--medium)}.low{background-color:var(--low)}.info{background-color:var(--info)}.unknown{background-color:var(--unknown)}.severity-legend{display:flex;flex-wrap:wrap;gap:12px 20px;font-size:12px}.severity-legend span{display:flex;align-items:center;gap:6px}.severity-legend i{width:8px;height:8px;border-radius:50%}.severity-legend b{color:var(--ink)}.controls{display:flex;align-items:end;gap:12px;flex-wrap:wrap;margin-top:24px;padding:14px}.controls label{display:grid;gap:5px;color:var(--muted);font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:.06em}.search-label{flex:1 1 280px}.controls input,.controls select,.controls button{min-height:42px;border:1px solid var(--line);border-radius:10px;background:#07110f;color:var(--ink);padding:0 12px;font:inherit}.controls input{width:100%}.view-actions{display:flex;gap:8px;margin-left:auto}.controls button{cursor:pointer;color:var(--mint)}.result-line{text-align:right;color:var(--muted);font-size:12px;padding:12px 2px}.result-line strong{color:var(--ink)}.findings{display:grid;gap:10px}.finding{overflow:hidden}.finding[hidden]{display:none}.finding summary{list-style:none;display:grid;grid-template-columns:auto minmax(0,1fr) auto auto;align-items:center;gap:14px;padding:17px 18px;cursor:pointer}.finding summary::-webkit-details-marker{display:none}.finding[open] summary{border-bottom:1px solid var(--line);background:rgba(55,227,155,.035)}.severity{display:inline-grid;place-items:center;min-width:72px;min-height:27px;border-radius:99px;color:#07110f;font-size:10px;font-weight:900;text-transform:uppercase;letter-spacing:.07em}.summary-copy{min-width:0}.summary-copy strong,.summary-copy small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.summary-copy strong{font-size:15px}.summary-copy small{color:var(--muted);font:11px ui-monospace,SFMono-Regular,Consolas,monospace;margin-top:4px}.state,.confidence{border:1px solid var(--line);border-radius:99px;padding:5px 9px;font-size:10px;font-weight:850;text-transform:uppercase;letter-spacing:.06em}.state.new{color:var(--critical);border-color:rgba(255,95,120,.35)}.state.updated{color:var(--medium);border-color:rgba(255,200,107,.35)}.state.absent{color:var(--low);border-color:rgba(123,217,255,.35)}.state.unchanged{color:var(--mint);border-color:rgba(140,246,195,.3)}.confidence,.record-count{color:var(--muted)}.record-count{font-size:11px;white-space:nowrap}.finding-body{padding:20px}.description{color:#c6d8d0;max-width:900px}.baseline-callout{display:flex;align-items:center;gap:10px;flex-wrap:wrap;border-left:3px solid var(--mint);padding:10px 12px;background:var(--panel2);border-radius:8px;font-size:12px}.baseline-callout.new{border-color:var(--critical)}.baseline-callout.updated{border-color:var(--medium)}.baseline-callout.absent{border-color:var(--low)}.baseline-callout span{color:var(--muted)}.facts{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:18px 0}.facts>div,.member dl>div{min-width:0}.facts dt,.member dt{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}.facts dd,.member dd{margin:4px 0 0;overflow-wrap:anywhere}.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}.evidence{margin-top:22px}.section-head{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:8px}.section-head h2{font-size:13px;margin:0}.section-head span{font-size:11px;color:var(--muted)}.reason-list,.blocker-list{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:10px}.reason-list article,.blocker-list article{display:flex;gap:10px;padding:11px;border:1px solid var(--line);border-radius:10px;background:#081310}.reason-list b{color:var(--mint)}.blocker-list b{color:var(--critical)}.reason-list strong,.blocker-list strong{display:block;font-size:11px;text-transform:uppercase;color:var(--muted)}.reason-list p,.blocker-list p{margin:2px 0;font-size:12px}.reason-list small{color:var(--muted)}.muted{color:var(--muted)}.member-list{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-top:10px}.member{border:1px solid var(--line);border-radius:12px;padding:12px;background:#081310}.member-head{display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:9px}.tool{display:grid;place-items:center;width:34px;height:34px;border-radius:10px;background:rgba(55,227,155,.1);color:var(--mint);font-size:11px;font-weight:900}.member-head strong,.member-head small{display:block}.member-head small{color:var(--muted);font-size:11px;overflow-wrap:anywhere}.mini-severity{font-size:10px;text-transform:uppercase;color:var(--muted)}.member dl{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin:12px 0 0}.member dd{font-size:11px}.references{display:grid;gap:7px;margin-top:10px}.references a{color:var(--mint);font-size:12px;overflow-wrap:anywhere}.notice{padding:14px;color:var(--muted);font-size:12px}.empty{text-align:center;color:var(--muted);padding:40px}footer{display:flex;justify-content:space-between;gap:24px;border-top:1px solid var(--line);padding:24px 0 40px;color:var(--muted);font-size:11px}footer strong{color:var(--mint)}footer span{max-width:750px;text-align:right}@media(max-width:800px){.stats{grid-template-columns:repeat(2,1fr)}.facts,.reason-list,.blocker-list,.member-list{grid-template-columns:1fr}.finding summary{grid-template-columns:auto minmax(0,1fr);}.state,.confidence,.record-count{grid-column:2}.hero-copy{padding-top:36px}.view-actions{width:100%;margin-left:0}.view-actions button{flex:1}footer{display:block}footer span{display:block;text-align:left;margin-top:8px}}@media(max-width:480px){.hero,main,footer{width:min(100% - 24px,1180px)}.stats{grid-template-columns:1fr}.finding summary{padding:14px}.severity{min-width:62px}.finding-body{padding:14px}}
` +
  String.raw`
.badges{display:flex;align-items:center;justify-content:flex-end;gap:5px;flex-wrap:wrap}.suppression{border:1px solid var(--line);border-radius:99px;padding:5px 9px;font-size:9px;font-weight:850;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}.suppression.active{color:var(--mint)}.suppression.suppressed{color:var(--medium);border-color:rgba(255,200,107,.35)}.suppression.non-finding{color:var(--low);border-color:rgba(123,217,255,.35)}.suppression-evidence{margin-top:10px;padding:9px;border:1px solid rgba(255,200,107,.22);border-radius:8px;background:rgba(255,200,107,.035);font-size:11px}.suppression-evidence>span{color:var(--medium);font-weight:800;text-transform:uppercase;letter-spacing:.05em}.suppression-evidence ul{margin:7px 0 0;padding-left:18px}.suppression-evidence li+li{margin-top:6px}.suppression-evidence p{margin:2px 0 0;color:var(--muted);overflow-wrap:anywhere}@media(max-width:800px){.badges{grid-column:2;justify-content:flex-start}}
`;

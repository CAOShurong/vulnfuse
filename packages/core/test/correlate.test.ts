import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  analyzeCoverage,
  compareCorrelations,
  correlateReports,
  explainMatch,
  exportBaselineDiff,
  exportCorrelation,
  parseReport,
  type CanonicalFinding,
  type ParsedReport,
} from "../src/index.js";

function fixture(name: string): string {
  return readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), "utf8");
}

function report(name: string) {
  return parseReport({ name, content: fixture(name) });
}

describe("explainable correlation", () => {
  it("collapses the same Log4Shell instance across Trivy and Grype", () => {
    const result = correlateReports([report("trivy.json"), report("grype.json")]);
    expect(result.summary.inputFindings).toBe(4);
    expect(result.summary.clusters).toBe(3);
    expect(result.summary.duplicatesCollapsed).toBe(1);
    const log4shell = result.clusters.find((cluster) =>
      cluster.identifiers.some((identifier) => identifier.value === "CVE-2021-44228"),
    );
    expect(log4shell?.members).toHaveLength(2);
    expect(log4shell?.sourceTools).toEqual(["Grype", "Trivy"]);
    expect(log4shell?.edges[0]?.explanation.reasons.map((reason) => reason.feature)).toEqual(
      expect.arrayContaining(["identifier", "component", "asset"]),
    );
  });

  it("keeps different assets separate in instance scope but merges a root cause", () => {
    const reports = [report("trivy.json"), report("snyk.json")];
    const instance = correlateReports(reports, { scope: "instance" });
    const rootCause = correlateReports(reports, { scope: "root-cause" });
    expect(instance.summary.clusters).toBe(3);
    expect(rootCause.summary.clusters).toBe(2);
    expect(rootCause.clusters.find((cluster) => cluster.members.length === 2)?.sourceTools).toEqual(
      ["Snyk", "Trivy"],
    );
  });

  it("uses blockers when explicit vulnerability identities conflict", () => {
    const base = report("trivy.json").findings[0] as CanonicalFinding;
    const conflict: CanonicalFinding = {
      ...base,
      id: "conflict",
      title: "Unrelated issue in the same component",
      identifiers: [{ scheme: "CVE", value: "CVE-2099-9999", relationship: "primary" }],
    };
    const explanation = explainMatch(base, conflict);
    expect(explanation.blockers.map((blocker) => blocker.feature)).toContain("identifier");
    expect(explanation.matched).toBe(false);
  });

  it("prevents a matched chain from carrying a hard blocker into one cluster", () => {
    const chain = [
      ["Scanner A", "CVE-2024-1000", "", "alpha", "rule-a"],
      ["Scanner B", "CVE-2024-1000", "CVE-2024-2000", "", "rule-a"],
      ["Scanner C", "CVE-2024-2000", "", "beta", "rule-c"],
    ].map(([tool, vulnerabilityId, aliases, component, ruleId]) =>
      parseReport({
        name: `${tool}.csv`,
        content: [
          "title,severity,vulnerability_id,aliases,component,version,asset,tool,kind,rule_id",
          `Remote execution issue,high,${vulnerabilityId},${aliases},${component},1.0,prod-api,${tool},sca,${ruleId}`,
        ].join("\n"),
      }),
    );

    const result = correlateReports(chain);
    expect(result.summary.clusters).toBe(2);
    expect(
      result.clusters.every((cluster) =>
        cluster.members.every((left, leftIndex) =>
          cluster.members
            .slice(leftIndex + 1)
            .every((right) => explainMatch(left, right).blockers.length === 0),
        ),
      ),
    ).toBe(true);
    expect(
      result.rejectedCandidates.some((edge) =>
        edge.explanation.blockers.some((blocker) => blocker.feature === "component"),
      ),
    ).toBe(true);
    expect(result.clusters.find((cluster) => cluster.members.length === 2)?.sourceTools).toEqual([
      "Scanner A",
      "Scanner B",
    ]);

    const partition = (reports: typeof chain) =>
      correlateReports(reports)
        .clusters.map((cluster) =>
          cluster.members
            .map((member) => member.id)
            .sort()
            .join("|"),
        )
        .sort();
    expect(partition([...chain].reverse())).toEqual(partition(chain));
  });

  it("fails visibly instead of skipping an excessive cluster-safety check", () => {
    const size = 1_416;
    const findings: CanonicalFinding[] = Array.from({ length: size }, (_, index) => ({
      id: `synthetic-${String(index).padStart(5, "0")}`,
      source: { tool: "Synthetic Scanner", report: "synthetic-chain.json" },
      kind: "sca",
      title: "Synthetic bridge candidate",
      severity: "medium",
      identifiers: [],
      fingerprints: {
        ...(index > 0 ? { left: `edge-${index - 1}` } : {}),
        ...(index < size - 1 ? { right: `edge-${index}` } : {}),
      },
      references: [],
      properties: {},
    }));
    const oversized: ParsedReport = {
      format: "vulnfuse",
      sourceName: "synthetic-chain.json",
      tool: "Synthetic Scanner",
      tools: ["Synthetic Scanner"],
      findings,
      warnings: [],
      metadata: {},
    };

    expect(() => correlateReports([oversized])).toThrow(
      /more than 1,000,000 cluster-safety comparisons/,
    );
  }, 20_000);

  it("produces stable cluster IDs", () => {
    const reports = [report("trivy.json"), report("grype.json")];
    expect(correlateReports(reports).clusters.map((cluster) => cluster.id)).toEqual(
      correlateReports(reports).clusters.map((cluster) => cluster.id),
    );
  });

  it("quantifies single-tool findings and pairwise overlap without voting on truth", () => {
    const coverage = correlateReports([report("trivy.json"), report("grype.json")]).summary
      .coverage;
    expect(coverage).toEqual({
      singleToolClusters: 2,
      multiToolClusters: 1,
      tools: [
        {
          tool: "Grype",
          reports: 1,
          sourceFindings: 2,
          clusters: 2,
          exclusiveClusters: 1,
          sharedClusters: 1,
        },
        {
          tool: "Trivy",
          reports: 1,
          sourceFindings: 2,
          clusters: 2,
          exclusiveClusters: 1,
          sharedClusters: 1,
        },
      ],
      pairs: [
        {
          leftTool: "Grype",
          rightTool: "Trivy",
          sharedClusters: 1,
          unionClusters: 3,
          overlapRatio: 0.3333,
        },
      ],
      pairwiseOmitted: false,
    });
  });

  it("attributes a mixed report to the tool on each source finding", () => {
    const mixed = parseReport({
      name: "mixed.csv",
      content: [
        "title,severity,component,tool",
        "Alpha finding,high,alpha-package,Alpha Scanner",
        "Beta finding,medium,beta-package,Beta Scanner",
      ].join("\n"),
    });
    const result = correlateReports([mixed]);
    expect(result.reports[0]?.tools).toEqual(["Alpha Scanner", "Beta Scanner"]);
    expect(result.summary.sourceTools).toEqual(["Alpha Scanner", "Beta Scanner"]);
    expect(result.summary.coverage.tools).toEqual([
      expect.objectContaining({ tool: "Alpha Scanner", reports: 1, sourceFindings: 1 }),
      expect.objectContaining({ tool: "Beta Scanner", reports: 1, sourceFindings: 1 }),
    ]);
  });

  it("retains tool attribution for empty multi-run SARIF", () => {
    const empty = parseReport({
      name: "empty.sarif",
      content: JSON.stringify({
        version: "2.1.0",
        runs: [
          { tool: { driver: { name: "Alpha", semanticVersion: "1.0.0" } }, results: [] },
          { tool: { driver: { name: "Beta", version: "2.0" } }, results: [] },
        ],
      }),
    });
    const result = correlateReports([empty]);
    expect(empty.tool).toBe("Alpha");
    expect(empty.tools).toEqual(["Alpha", "Beta"]);
    expect(result.summary.sourceTools).toEqual(["Alpha", "Beta"]);
    expect(result.summary.coverage.tools).toEqual([
      expect.objectContaining({ tool: "Alpha", reports: 1, sourceFindings: 0 }),
      expect.objectContaining({ tool: "Beta", reports: 1, sourceFindings: 0 }),
    ]);
  });

  it("reports zero overlap when tools produce no clusters", () => {
    expect(
      analyzeCoverage(
        [
          { tool: "Empty A", findings: 0 },
          { tool: "Empty B", findings: 0 },
        ],
        [],
      ).pairs[0],
    ).toMatchObject({ sharedClusters: 0, unionClusters: 0, overlapRatio: 0 });
  });

  it("omits quadratic pair rows when a report set names many tools", () => {
    const coverage = analyzeCoverage(
      Array.from({ length: 21 }, (_, index) => ({ tool: `Tool ${index}`, findings: 0 })),
      [],
    );
    expect(coverage.pairs).toEqual([]);
    expect(coverage.pairwiseOmitted).toBe(true);
    expect(coverage.tools).toHaveLength(21);
  });
});

describe("exports", () => {
  const result = correlateReports([report("trivy.json"), report("grype.json")]);

  it("exports canonical JSON", () => {
    const value = JSON.parse(exportCorrelation(result, "json")) as { schemaVersion: string };
    expect(value.schemaVersion).toBe("1.0");
  });

  it("exports valid SARIF", () => {
    const value = JSON.parse(exportCorrelation(result, "sarif")) as {
      version: string;
      runs: unknown[];
    };
    expect(value.version).toBe("2.1.0");
    expect(value.runs).toHaveLength(1);
  });

  it("exports reviewable Markdown and CSV", () => {
    const markdown = exportCorrelation(result, "markdown");
    expect(markdown).toContain("Why merged");
    expect(markdown).toContain("## Scanner coverage");
    expect(markdown).toContain("Grype / Trivy | 1 | 3 | 33.3%");
    expect(exportCorrelation(result, "csv")).toContain("duplicates_collapsed");
  });

  it("exports a self-contained interactive HTML report", () => {
    const htmlInput = structuredClone(result);
    const merged = htmlInput.clusters.find((cluster) => cluster.members.length > 1);
    const nonPrimary = merged?.members.find((member) => member.id !== merged.primary.id);
    expect(nonPrimary).toBeDefined();
    if (!nonPrimary) return;
    nonPrimary.references.push("https://example.com/member-only-evidence");

    const html = exportCorrelation(htmlInput, "html");
    expect(html).toContain("<!doctype html>");
    expect(html).toContain("Content-Security-Policy");
    expect(html).toContain('id="search"');
    expect(html).toContain('id="tool-filter"');
    expect(html).toContain('id="coverage-filter"');
    expect(html).toContain("Scanner divergence");
    expect(html).toContain("Grype / Trivy");
    expect(html).toContain('data-coverage="multi"');
    expect(html).toContain('data-coverage="single"');
    expect(html).toContain("This self-contained file makes no network requests.");
    expect(html).toContain("https://example.com/member-only-evidence");
    expect(html).not.toMatch(/<(script|link)[^>]+src=/i);
    expect(html).not.toMatch(/<link[^>]+href=/i);
  });

  it("escapes untrusted HTML and refuses active reference schemes", () => {
    const special = parseReport({
      name: "hostile.csv",
      content:
        'title,severity,component,tool\n"</script><img src=x onerror=alert(1)>",high,widget,"</option><script>alert(2)</script>"',
    });
    const correlated = correlateReports([special]);
    const first = correlated.clusters[0];
    expect(first).toBeDefined();
    if (!first) return;
    first.primary.references = ["javascript:alert(1)", "https://example.com/advisory?q=<x>"];
    const html = exportCorrelation(correlated, "html");
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("javascript:alert(1)");
    expect(html).not.toContain("</option><script>alert(2)</script>");
    expect(html).toContain("&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;");
    expect(html).toContain("&lt;/option&gt;&lt;script&gt;alert(2)&lt;/script&gt;");
    expect(html).toContain("https://example.com/advisory?q=%3Cx%3E");
  });

  it("uses valid code spans for untrusted component text", () => {
    const special = parseReport({
      name: "special.csv",
      content: 'title,component,version,tool\n"Backtick ` and *","pkg\\name`part","1.0",Tool',
    });
    const markdown = exportCorrelation(correlateReports([special]), "markdown");
    expect(markdown).toContain("### Backtick \\` and \\*");
    expect(markdown).toContain("**Component:** ``pkg\\name`part@1.0``");
  });
});

describe("baseline comparison", () => {
  it("marks stable clusters unchanged and new evidence as new", () => {
    const baseline = correlateReports([report("trivy.json"), report("grype.json")]);
    const unchanged = compareCorrelations(
      baseline,
      correlateReports([report("trivy.json"), report("grype.json")]),
    );
    expect(unchanged.summary).toMatchObject({ new: 0, updated: 0, absent: 0, unchanged: 3 });

    const current = correlateReports([
      report("trivy.json"),
      report("grype.json"),
      report("generic.csv"),
    ]);
    const diff = compareCorrelations(baseline, current);
    expect(diff.summary.new).toBeGreaterThan(0);
    expect(diff.items.filter((item) => item.state === "new")).not.toHaveLength(0);
  });

  it("distinguishes updated evidence from findings absent in the current run", () => {
    const baseline = correlateReports([report("trivy.json"), report("grype.json")]);
    const current = correlateReports([report("trivy.json")]);
    const diff = compareCorrelations(baseline, current);
    expect(diff.summary).toMatchObject({ new: 0, updated: 1, absent: 1, unchanged: 1 });
    expect(diff.items.find((item) => item.state === "updated")?.changedFields).toEqual(
      expect.arrayContaining(["source-tools", "source-records"]),
    );
  });

  it("exports baseline states in SARIF, Markdown, CSV, and portable HTML", () => {
    const baseline = correlateReports([report("trivy.json")]);
    const current = correlateReports([report("trivy.json"), report("generic.csv")]);
    const diff = compareCorrelations(baseline, current);
    const sarif = JSON.parse(exportBaselineDiff(diff, "sarif")) as {
      runs: Array<{ results: Array<{ baselineState?: string; partialFingerprints?: unknown }> }>;
    };
    expect(sarif.runs[0]?.results.every((result) => result.baselineState)).toBe(true);
    expect(sarif.runs[0]?.results.every((result) => result.partialFingerprints)).toBe(true);
    const markdown = exportBaselineDiff(diff, "markdown");
    expect(markdown).toContain("VulnFuse baseline comparison");
    expect(markdown).toContain("## Current-run scanner coverage");
    expect(exportBaselineDiff(diff, "csv")).toContain("baseline_state");
    const html = exportBaselineDiff(diff, "html");
    expect(html).toContain('id="state-filter"');
    expect(html).toContain('data-state="new"');
    expect(html).toContain("absent means a cluster was not observed");
    expect(html).toContain("Coverage below describes current-run clusters");
  });

  it("rejects comparisons made with different scopes", () => {
    const baseline = correlateReports([report("trivy.json")], { scope: "instance" });
    const current = correlateReports([report("trivy.json")], { scope: "root-cause" });
    expect(() => compareCorrelations(baseline, current)).toThrow(/scope/);
  });

  it("fails visibly before a giant cluster can trigger excessive member comparisons", () => {
    const original = correlateReports([report("trivy.json")]);
    const firstCluster = original.clusters[0];
    const firstMember = firstCluster?.members[0];
    expect(firstCluster).toBeDefined();
    expect(firstMember).toBeDefined();
    if (!firstCluster || !firstMember) return;
    const baseline = {
      ...original,
      clusters: [
        { ...firstCluster, id: "baseline-large", members: Array(2_000).fill(firstMember) },
      ],
    };
    const current = {
      ...original,
      clusters: [{ ...firstCluster, id: "current-large", members: Array(1_001).fill(firstMember) }],
    };
    expect(() => compareCorrelations(baseline, current)).toThrow(/source-record comparisons/);
  });
});

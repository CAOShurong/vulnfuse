import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  analyzeCoverage,
  compareCorrelations,
  correlateReports,
  describeScanSetChange,
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
  it("correlates OpenVEX component evidence without applying its status as a verdict", () => {
    const parsedVex = report("openvex.json");
    const vexFinding = parsedVex.findings[0];
    expect(vexFinding).toBeDefined();
    if (!vexFinding) return;
    const scanner = parseReport({
      name: "scanner.csv",
      content:
        "vulnerability_id,title,severity,purl,tool\n" +
        'CVE-2024-32002,"CVE-2024-32002 in pkg:apk/alpine/git@2.45.2-r0?arch=x86_64",high,"pkg:apk/alpine/git@2.45.2-r0?arch=x86_64",Other Scanner\n',
    });

    const result = correlateReports([{ ...parsedVex, findings: [vexFinding] }, scanner], {
      scope: "root-cause",
    });

    expect(result.clusters).toHaveLength(1);
    expect(result.clusters[0]).toMatchObject({ suppressed: false, nonFinding: false });
    expect(result.clusters[0]?.members).toHaveLength(2);
    expect(result.clusters[0]?.sourceTools).toEqual([
      "OpenVEX (Example VEX Producer)",
      "Other Scanner",
    ]);
  });

  it("correlates a BOM-linked external VEX PURL with another scanner", () => {
    const parsedVex = report("cyclonedx-bomlink.json");
    const vexFinding = parsedVex.findings[0];
    expect(vexFinding).toBeDefined();
    if (!vexFinding) return;
    const scanner = parseReport({
      name: "scanner.csv",
      content:
        "vulnerability_id,title,severity,purl,tool\n" +
        'CVE-2018-7489,"CVE-2018-7489 in pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.0?type=jar",high,"pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.0?type=jar",Other Scanner\n',
    });

    const result = correlateReports([{ ...parsedVex, findings: [vexFinding] }, scanner], {
      scope: "root-cause",
    });

    expect(result.clusters).toHaveLength(1);
    expect(result.clusters[0]?.members).toHaveLength(2);
    expect(result.clusters[0]?.sourceTools).toEqual(["CycloneDX VEX Producer", "Other Scanner"]);
  });

  it("separates non-finding SARIF evidence from active and suppressed clusters", () => {
    const parsed = report("sarif-result-kinds.json");
    const result = correlateReports([parsed]);

    expect(result.summary).toMatchObject({
      inputFindings: 10,
      clusters: 10,
      activeClusters: 7,
      suppressedClusters: 0,
      nonFindingClusters: 3,
    });
    expect(result.summary.nonFindingBySeverity.info).toBe(3);
    expect(result.summary.activeBySeverity.info).toBe(4);
    expect(result.clusters.filter((cluster) => cluster.nonFinding)).toHaveLength(3);

    const pass = parsed.findings[0];
    const fail = parsed.findings[5];
    expect(pass).toBeDefined();
    expect(fail).toBeDefined();
    if (!pass || !fail) return;
    const mixed = correlateReports(
      [
        {
          ...parsed,
          sourceName: "pass.sarif",
          findings: [
            {
              ...pass,
              id: "pass-record",
              title: "Shared rule outcome",
              ruleId: "SHARED001",
              identifiers: [],
              fingerprints: {},
              location: { uri: "src/shared.c", startLine: 12 },
              component: { path: "src/shared.c" },
              asset: { type: "file", name: "src/shared.c", key: "src/shared.c" },
            },
          ],
        },
        {
          ...parsed,
          sourceName: "fail.sarif",
          tool: "Second Producer",
          tools: ["Second Producer"],
          findings: [
            {
              ...fail,
              id: "fail-record",
              source: { ...fail.source, tool: "Second Producer", report: "fail.sarif" },
              title: "Shared rule outcome",
              ruleId: "SHARED001",
              identifiers: [],
              fingerprints: {},
              location: { uri: "src/shared.c", startLine: 12 },
              component: { path: "src/shared.c" },
              asset: { type: "file", name: "src/shared.c", key: "src/shared.c" },
            },
          ],
        },
      ],
      { threshold: 0 },
    );
    expect(mixed.clusters).toHaveLength(1);
    expect(mixed.clusters[0]).toMatchObject({ nonFinding: false, suppressed: false });
    expect(mixed.summary).toMatchObject({
      activeClusters: 1,
      suppressedClusters: 0,
      nonFindingClusters: 0,
    });

    const csv = exportCorrelation(result, "csv");
    expect(csv).toContain("disposition");
    expect(csv).toContain("non-finding");

    const markdown = exportCorrelation(result, "markdown");
    expect(markdown).toContain("7 active, 0 effectively suppressed, 3 non-finding");
    expect(markdown).toContain("**Disposition:** non-finding evidence");

    const sarif = JSON.parse(exportCorrelation(result, "sarif")) as {
      runs: Array<{
        results: Array<{ properties?: { nonFinding?: boolean } }>;
        properties?: { nonFindingClusters?: Array<{ nonFinding?: boolean }> };
      }>;
    };
    expect(sarif.runs[0]?.results).toHaveLength(7);
    expect(sarif.runs[0]?.results.some((item) => item.properties?.nonFinding)).toBe(false);
    expect(sarif.runs[0]?.properties?.nonFindingClusters).toHaveLength(3);
    expect(
      sarif.runs[0]?.properties?.nonFindingClusters?.every((cluster) => cluster.nonFinding),
    ).toBe(true);

    const html = exportCorrelation(result, "html");
    expect(html).toContain('id="disposition-filter"');
    expect(html).toContain('data-disposition="non-finding"');
  });

  it("keeps suppressed evidence but separates it from active clusters", () => {
    const suppressedReport = report("sarif-suppressed.json");
    const suppressedOnly = correlateReports([suppressedReport]);
    expect(suppressedOnly.summary).toMatchObject({
      clusters: 2,
      activeClusters: 0,
      suppressedClusters: 2,
    });
    expect(suppressedOnly.summary.bySeverity.high).toBe(2);
    expect(suppressedOnly.summary.activeBySeverity.high).toBe(0);
    expect(suppressedOnly.clusters.every((cluster) => cluster.suppressed)).toBe(true);

    const first = suppressedReport.findings[0];
    expect(first).toBeDefined();
    if (!first) return;
    const activeReport: ParsedReport = {
      ...suppressedReport,
      sourceName: "active.json",
      tool: "Active Scanner",
      tools: ["Active Scanner"],
      findings: [
        {
          ...first,
          id: "active-corroboration",
          source: { ...first.source, tool: "Active Scanner", report: "active.json" },
          suppressed: false,
          suppressions: [],
        },
      ],
    };
    const mixed = correlateReports([suppressedReport, activeReport]);
    const corroborated = mixed.clusters.find((cluster) => cluster.members.length === 2);
    expect(corroborated?.suppressed).toBe(false);
    expect(mixed.summary).toMatchObject({ activeClusters: 1, suppressedClusters: 1 });
  });

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

  it("bounds GitHub-facing SARIF rule tags without dropping identifier evidence", () => {
    const aliasRich = structuredClone(result);
    const cluster = aliasRich.clusters[0];
    expect(cluster).toBeDefined();
    if (!cluster) return;
    cluster.identifiers = Array.from({ length: 30 }, (_, index) => ({
      scheme: "ALIAS",
      value: `ALIAS-${String(index + 1).padStart(2, "0")}`,
      relationship: "alias" as const,
    })).reverse();

    const sarif = JSON.parse(exportCorrelation(aliasRich, "sarif")) as {
      runs: Array<{
        tool: {
          driver: {
            rules: Array<{
              properties: {
                tags: string[];
                vulnfuseOmittedIdentifierTagCount?: number;
              };
            }>;
          };
        };
        results: Array<{ properties: { identifiers: unknown[] } }>;
      }>;
    };
    const ruleProperties = sarif.runs[0]?.tool.driver.rules[0]?.properties;

    expect(ruleProperties?.tags).toEqual([
      "security",
      cluster.primary.kind,
      "ALIAS-01",
      "ALIAS-02",
      "ALIAS-03",
      "ALIAS-04",
      "ALIAS-05",
      "ALIAS-06",
      "ALIAS-07",
    ]);
    expect(ruleProperties?.vulnfuseOmittedIdentifierTagCount).toBe(23);
    expect(sarif.runs[0]?.results[0]?.properties.identifiers).toHaveLength(30);
  });

  it("bounds hosted SARIF text without splitting Unicode or losing original evidence", () => {
    const longMetadata = structuredClone(result);
    const cluster = longMetadata.clusters[0];
    expect(cluster).toBeDefined();
    if (!cluster) return;
    const originalName = `CUSTOM-${"N".repeat(246)}😀tail`;
    const originalTitle = `${"T".repeat(1022)}😀title-tail`;
    const originalDescription = `${"D".repeat(1022)}😀description-tail`;
    cluster.identifiers = [
      { scheme: "CUSTOM", value: originalName, relationship: "primary" },
      ...Array.from({ length: 29 }, (_, index) => ({
        scheme: "ALIAS",
        value: `ALIAS-${String(index + 1).padStart(2, "0")}`,
        relationship: "alias" as const,
      })),
    ];
    cluster.primary.title = originalTitle;
    cluster.primary.description = originalDescription;

    const sarif = JSON.parse(exportCorrelation(longMetadata, "sarif")) as {
      runs: Array<{
        tool: {
          driver: {
            rules: Array<{
              name: string;
              shortDescription: { text: string };
              fullDescription: { text: string };
              properties: {
                vulnfuseOriginalName?: string;
                vulnfuseOriginalShortDescription?: string;
                vulnfuseOriginalFullDescription?: string;
                vulnfuseTruncatedFields?: string[];
              };
            }>;
          };
        };
        results: Array<{
          message: { text: string };
          properties: { vulnfuseOriginalMessage?: string };
        }>;
      }>;
    };
    const rule = sarif.runs[0]?.tool.driver.rules[0];
    const sarifResult = sarif.runs[0]?.results[0];

    expect(rule?.name.length).toBeLessThanOrEqual(255);
    expect(rule?.shortDescription.text.length).toBeLessThanOrEqual(1024);
    expect(rule?.fullDescription.text.length).toBeLessThanOrEqual(1024);
    expect(sarifResult?.message.text.length).toBeLessThanOrEqual(1024);
    expect(rule?.name.endsWith("…")).toBe(true);
    expect(rule?.shortDescription.text.endsWith("…")).toBe(true);
    expect(rule?.fullDescription.text.endsWith("…")).toBe(true);
    expect(sarifResult?.message.text.endsWith("…")).toBe(true);
    expect([...(rule?.name ?? "")]).not.toContain("\uFFFD");
    expect(rule?.properties).toMatchObject({
      vulnfuseOriginalName: originalName,
      vulnfuseOriginalShortDescription: originalTitle,
      vulnfuseOriginalFullDescription: originalDescription,
      vulnfuseTruncatedFields: ["name", "shortDescription.text", "fullDescription.text"],
    });
    expect(sarifResult?.properties.vulnfuseOriginalMessage).toContain(originalTitle);

    const baselineSarif = JSON.parse(
      exportBaselineDiff(compareCorrelations(correlateReports([]), longMetadata), "sarif"),
    ) as {
      runs: Array<{
        tool: {
          driver: {
            rules: Array<{
              name: string;
              properties: {
                tags: string[];
                vulnfuseOriginalName?: string;
                vulnfuseOmittedIdentifierTagCount?: number;
              };
            }>;
          };
        };
        results: Array<{ message: { text: string } }>;
      }>;
    };
    const baselineRule = baselineSarif.runs[0]?.tool.driver.rules[0];
    expect(baselineRule?.name.length).toBeLessThanOrEqual(255);
    expect(baselineRule?.properties.tags).toHaveLength(9);
    expect(baselineRule?.properties.vulnfuseOmittedIdentifierTagCount).toBe(23);
    expect(baselineRule?.properties.vulnfuseOriginalName).toBe(originalName);
    expect(baselineSarif.runs[0]?.results[0]?.message.text.length).toBeLessThanOrEqual(1024);
  });

  it("anchors only locationless hosted SARIF results when the user supplies a fallback", () => {
    const openVex = correlateReports([report("openvex.json")]);
    const withoutFallback = JSON.parse(exportCorrelation(openVex, "sarif")) as {
      runs: Array<{ results: Array<{ locations?: unknown[] }> }>;
    };
    expect(withoutFallback.runs[0]?.results.every((item) => !item.locations)).toBe(true);

    const fallback = "security/openvex.json";
    const anchored = JSON.parse(
      exportCorrelation(openVex, "sarif", { sarifFallbackLocation: fallback }),
    ) as {
      runs: Array<{
        results: Array<{
          locations?: Array<{
            physicalLocation: {
              artifactLocation: { uri: string };
              region?: { startLine: number };
            };
          }>;
          properties: { vulnfuseLocationProvenance?: string };
        }>;
      }>;
    };
    expect(anchored.runs[0]?.results).toHaveLength(3);
    for (const item of anchored.runs[0]?.results ?? []) {
      expect(item.locations?.[0]?.physicalLocation.artifactLocation.uri).toBe(fallback);
      expect(item.locations?.[0]?.physicalLocation.region?.startLine).toBe(1);
      expect(item.properties.vulnfuseLocationProvenance).toBe("user-supplied-fallback");
    }

    const mixed = JSON.parse(
      exportCorrelation(correlateReports([report("trivy.json"), report("openvex.json")]), "sarif", {
        sarifFallbackLocation: fallback,
      }),
    ) as {
      runs: Array<{
        results: Array<{
          locations?: Array<{
            physicalLocation: {
              artifactLocation: { uri: string };
              region?: { startLine: number };
            };
          }>;
          properties: { vulnfuseLocationProvenance?: string };
        }>;
      }>;
    };
    const mixedResults = mixed.runs[0]?.results ?? [];
    expect(
      mixedResults.filter(
        (item) => item.locations?.[0]?.physicalLocation.artifactLocation.uri === fallback,
      ),
    ).toHaveLength(3);
    expect(
      mixedResults.filter(
        (item) => item.locations?.[0]?.physicalLocation.artifactLocation.uri === "app.jar",
      ),
    ).toHaveLength(2);
    expect(
      mixedResults
        .filter((item) => item.locations?.[0]?.physicalLocation.artifactLocation.uri === "app.jar")
        .every((item) => item.properties.vulnfuseLocationProvenance === undefined),
    ).toBe(true);

    const baseline = JSON.parse(
      exportBaselineDiff(compareCorrelations(correlateReports([]), openVex), "sarif", {
        sarifFallbackLocation: fallback,
      }),
    ) as {
      runs: Array<{
        results: Array<{
          locations?: Array<{
            physicalLocation: {
              artifactLocation: { uri: string };
              region?: { startLine: number };
            };
          }>;
          properties: { vulnfuseLocationProvenance?: string };
        }>;
      }>;
    };
    expect(baseline.runs[0]?.results).toHaveLength(3);
    expect(
      baseline.runs[0]?.results.every(
        (item) =>
          item.locations?.[0]?.physicalLocation.artifactLocation.uri === fallback &&
          item.locations?.[0]?.physicalLocation.region?.startLine === 1 &&
          item.properties.vulnfuseLocationProvenance === "user-supplied-fallback",
      ),
    ).toBe(true);

    for (const invalid of [
      "",
      "/absolute.json",
      "C:/absolute.json",
      "https://example.test/report.json",
      "../outside.json",
      "security/../outside.json",
      "security/%2e%2e/outside.json",
      "security/%2foutside.json",
      "security/%252foutside.json",
      "security/report%20name.json",
      "security/report%3fquery.json",
      "security/report%23fragment.json",
      "security\\report.json",
      "security//report.json",
      "security/report.json/",
      "security/report.json?query=1",
      "security/report.json#fragment",
      " security/report.json",
    ]) {
      expect(() => exportCorrelation(openVex, "sarif", { sarifFallbackLocation: invalid })).toThrow(
        /SARIF fallback location/,
      );
    }
    expect(() => exportCorrelation(openVex, "json", { sarifFallbackLocation: fallback })).toThrow(
      /only be used with SARIF output/,
    );
  });

  it("exports reviewable Markdown and CSV", () => {
    const markdown = exportCorrelation(result, "markdown");
    expect(markdown).toContain("Why merged");
    expect(markdown).toContain("## Scanner coverage");
    expect(markdown).toContain("Grype / Trivy | 1 | 3 | 33.3%");
    expect(exportCorrelation(result, "csv")).toContain("duplicates_collapsed");
  });

  it("preserves suppression evidence across reviewable export formats", () => {
    const suppressed = correlateReports([report("sarif-suppressed.json")]);

    const csv = exportCorrelation(suppressed, "csv");
    expect(csv).toContain("suppressed");
    expect(csv).toContain("true");

    const markdown = exportCorrelation(suppressed, "markdown");
    expect(markdown).toContain("0 active, 2 effectively suppressed");
    expect(markdown).toContain("**Disposition:** effectively suppressed");
    expect(markdown).toContain("Reviewed \\<script\\>alert");

    const sarif = JSON.parse(exportCorrelation(suppressed, "sarif")) as {
      runs: Array<{
        results: Array<{
          suppressions?: Array<{ kind?: string; status?: string; justification?: string }>;
          properties?: { suppressed?: boolean };
        }>;
      }>;
    };
    const exportedSuppressions = sarif.runs[0]?.results.flatMap((item) => item.suppressions ?? []);
    expect(exportedSuppressions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "inSource" }),
        expect.objectContaining({ kind: "external", status: "accepted" }),
      ]),
    );
    expect(sarif.runs[0]?.results.every((item) => item.properties?.suppressed)).toBe(true);

    const html = exportCorrelation(suppressed, "html");
    expect(html).toContain('id="disposition-filter"');
    expect(html).toContain('data-disposition="suppressed"');
    expect(html).toContain("Reviewed &lt;script&gt;alert(&#39;not markup&#39;)&lt;/script&gt;");
    expect(html).not.toContain("<script>alert('not markup')</script>");
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
  it("reports suppression changes while severity gates can count only active new clusters", () => {
    const parsed = report("sarif-suppressed.json");
    const first = parsed.findings[0];
    expect(first).toBeDefined();
    if (!first) return;
    const currentReport: ParsedReport = { ...parsed, findings: [first] };
    const activeReport: ParsedReport = {
      ...currentReport,
      findings: [{ ...first, suppressed: false, suppressions: [] }],
    };

    const changed = compareCorrelations(
      correlateReports([activeReport]),
      correlateReports([currentReport]),
    );
    expect(changed.summary).toMatchObject({ new: 0, updated: 1, unchanged: 0 });
    expect(changed.items[0]?.changedFields).toContain("suppression");

    const empty = correlateReports([
      parseReport({
        name: "empty.sarif",
        content: JSON.stringify({
          version: "2.1.0",
          runs: [{ tool: { driver: { name: parsed.tool } }, results: [] }],
        }),
      }),
    ]);
    const added = compareCorrelations(empty, correlateReports([currentReport]));
    expect(added.summary.newBySeverity.high).toBe(1);
    expect(added.summary.newActiveBySeverity.high).toBe(0);

    expect(exportBaselineDiff(changed, "csv")).toContain("suppressed");
    expect(exportBaselineDiff(changed, "markdown")).toContain(
      "**Disposition:** effectively suppressed",
    );
    const sarif = JSON.parse(exportBaselineDiff(changed, "sarif")) as {
      runs: Array<{
        results: Array<{ suppressions?: unknown[]; properties?: { suppressed?: boolean } }>;
      }>;
    };
    expect(sarif.runs[0]?.results[0]?.suppressions).toHaveLength(1);
    expect(sarif.runs[0]?.results[0]?.properties?.suppressed).toBe(true);
    expect(exportBaselineDiff(changed, "html")).toContain('data-disposition="suppressed"');

    const nonFindingReport = report("sarif-result-kinds.json");
    const nonFindingOnly: ParsedReport = {
      ...nonFindingReport,
      findings: nonFindingReport.findings.filter((finding) => finding.nonFinding),
    };
    const nonFindingAdded = compareCorrelations(empty, correlateReports([nonFindingOnly]));
    expect(nonFindingAdded.summary.newBySeverity.info).toBe(3);
    expect(nonFindingAdded.summary.newActiveBySeverity.info).toBe(0);
  });

  it("marks stable clusters unchanged and new evidence as new", () => {
    const baseline = correlateReports([report("trivy.json"), report("grype.json")]);
    const unchanged = compareCorrelations(
      baseline,
      correlateReports([report("trivy.json"), report("grype.json")]),
    );
    expect(unchanged.summary).toMatchObject({ new: 0, updated: 0, absent: 0, unchanged: 3 });
    expect(unchanged.scanSetChange).toEqual({
      detected: false,
      addedTools: [],
      removedTools: [],
      changedReportCounts: [],
      changedToolVersions: [],
      changedSarifAutomationCategories: [],
    });
    expect(describeScanSetChange(unchanged.scanSetChange)).toBe(
      "Scan set did not change by tool names, per-tool report counts, embedded tool versions, or SARIF automation categories.",
    );

    const current = correlateReports([
      report("trivy.json"),
      report("grype.json"),
      report("generic.csv"),
    ]);
    const diff = compareCorrelations(baseline, current);
    expect(diff.summary.new).toBeGreaterThan(0);
    expect(diff.items.filter((item) => item.state === "new")).not.toHaveLength(0);
    expect(diff.scanSetChange).toMatchObject({
      detected: true,
      addedTools: ["Legacy Scanner"],
      removedTools: [],
    });
  });

  it("detects per-tool report-count drift even when the scanner names match", () => {
    const baseline = correlateReports([report("trivy.json")]);
    const current = correlateReports([report("trivy.json"), report("trivy.json")]);

    expect(compareCorrelations(baseline, current).scanSetChange).toEqual({
      detected: true,
      addedTools: [],
      removedTools: [],
      changedReportCounts: [{ tool: "Trivy", baseline: 1, current: 2 }],
      changedToolVersions: [],
      changedSarifAutomationCategories: [],
    });
  });

  it("detects embedded tool-version drift with stable scanner names and report counts", () => {
    const sarif = (version?: string) =>
      parseReport({
        name: "empty.sarif",
        content: JSON.stringify({
          version: "2.1.0",
          runs: [
            {
              tool: {
                driver: {
                  name: "CodeQL",
                  ...(version ? { semanticVersion: version } : {}),
                },
              },
              results: [],
            },
          ],
        }),
      });

    const changed = compareCorrelations(
      correlateReports([sarif("2.20.0")]),
      correlateReports([sarif("2.26.2")]),
    );
    expect(changed.scanSetChange).toEqual({
      detected: true,
      addedTools: [],
      removedTools: [],
      changedReportCounts: [],
      changedToolVersions: [
        {
          tool: "CodeQL",
          baseline: { versions: ["2.20.0"], unversionedReports: 0 },
          current: { versions: ["2.26.2"], unversionedReports: 0 },
        },
      ],
      changedSarifAutomationCategories: [],
    });
    expect(describeScanSetChange(changed.scanSetChange)).toContain(
      'embedded versions "CodeQL" ["2.20.0"] to ["2.26.2"]',
    );

    const sarifExport = JSON.parse(exportBaselineDiff(changed, "sarif")) as {
      runs: Array<{
        invocations: Array<{
          properties?: {
            scanSetChange?: {
              changedToolVersions?: Array<{ tool?: string }>;
            };
          };
        }>;
      }>;
    };
    expect(
      sarifExport.runs[0]?.invocations[0]?.properties?.scanSetChange?.changedToolVersions,
    ).toEqual([expect.objectContaining({ tool: "CodeQL" })]);
    for (const format of ["markdown", "html"] as const) {
      const exported = exportBaselineDiff(changed, format);
      const visibleText = exported.replaceAll("\\", "");
      expect(visibleText).toContain("embedded versions");
      expect(visibleText).toContain("2.20.0");
      expect(visibleText).toContain("2.26.2");
    }

    const versionedFindingReport = (version: string) => {
      const document = JSON.parse(fixture("sarif.json")) as {
        runs: Array<{ tool: { driver: { semanticVersion: string } } }>;
      };
      document.runs[0]!.tool.driver.semanticVersion = version;
      return parseReport({ name: `codeql-${version}.sarif`, content: JSON.stringify(document) });
    };
    const csv = exportBaselineDiff(
      compareCorrelations(
        correlateReports([versionedFindingReport("2.20.0")]),
        correlateReports([versionedFindingReport("2.26.2")]),
      ),
      "csv",
    );
    expect(csv).toContain("embedded versions");
    expect(csv).toContain("2.20.0");
    expect(csv).toContain("2.26.2");

    const evidenceLost = compareCorrelations(
      correlateReports([sarif("2.26.2")]),
      correlateReports([sarif()]),
    );
    expect(evidenceLost.scanSetChange.detected).toBe(true);
    expect(evidenceLost.scanSetChange.changedToolVersions).toEqual([
      {
        tool: "CodeQL",
        baseline: { versions: ["2.26.2"], unversionedReports: 0 },
        current: { versions: [], unversionedReports: 1 },
      },
    ]);

    const unchanged = compareCorrelations(
      correlateReports([sarif("2.26.2")]),
      correlateReports([sarif("2.26.2")]),
    );
    expect(unchanged.scanSetChange.detected).toBe(false);
    expect(unchanged.scanSetChange.changedToolVersions).toEqual([]);
  });

  it("detects SARIF automation-category drift without changing zero-result findings", () => {
    const sarif = (id?: string) =>
      parseReport({
        name: "empty.sarif",
        content: JSON.stringify({
          version: "2.1.0",
          runs: [
            {
              tool: { driver: { name: "CodeScanner", semanticVersion: "1.2.3" } },
              ...(id ? { automationDetails: { id } } : {}),
              results: [],
            },
          ],
        }),
      });

    const changed = compareCorrelations(
      correlateReports([sarif("monorepo/main/2026-08-11")]),
      correlateReports([sarif("monorepo/release/2026-08-12")]),
    );
    expect(changed.summary).toMatchObject({
      baselineClusters: 0,
      currentClusters: 0,
      new: 0,
      absent: 0,
    });
    expect(changed.scanSetChange.changedSarifAutomationCategories).toEqual([
      {
        tool: "CodeScanner",
        baseline: { categories: ["monorepo/main"], uncategorizedRuns: 0 },
        current: { categories: ["monorepo/release"], uncategorizedRuns: 0 },
      },
    ]);
    expect(changed.scanSetChange.detected).toBe(true);
    expect(describeScanSetChange(changed.scanSetChange)).toContain(
      'SARIF automation categories "CodeScanner"',
    );
    expect(JSON.parse(exportBaselineDiff(changed, "json"))).toMatchObject({
      scanSetChange: { changedSarifAutomationCategories: [{ tool: "CodeScanner" }] },
    });

    const evidenceLost = compareCorrelations(
      correlateReports([sarif("monorepo/main/")]),
      correlateReports([sarif()]),
    );
    expect(evidenceLost.scanSetChange.changedSarifAutomationCategories).toEqual([
      {
        tool: "CodeScanner",
        baseline: { categories: ["monorepo/main"], uncategorizedRuns: 0 },
        current: { categories: [], uncategorizedRuns: 1 },
      },
    ]);

    const sarifExport = JSON.parse(exportBaselineDiff(changed, "sarif")) as {
      runs: Array<{
        invocations: Array<{
          properties?: {
            scanSetChange?: { changedSarifAutomationCategories?: unknown[] };
          };
        }>;
      }>;
    };
    expect(
      sarifExport.runs[0]?.invocations[0]?.properties?.scanSetChange
        ?.changedSarifAutomationCategories,
    ).toHaveLength(1);
    for (const format of ["markdown", "html"] as const) {
      const exported = exportBaselineDiff(changed, format).replaceAll("\\", "");
      expect(exported).toContain("SARIF automation categories");
      expect(exported).toContain("monorepo/main");
      expect(exported).toContain("monorepo/release");
    }

    const findingReport = (category: string) => {
      const document = JSON.parse(fixture("sarif.json")) as {
        runs: Array<Record<string, unknown>>;
      };
      document.runs[0]!["automationDetails"] = { id: `${category}/2026-08-12` };
      return parseReport({
        name: `${category.replaceAll("/", "-")}.sarif`,
        content: JSON.stringify(document),
      });
    };
    const csv = exportBaselineDiff(
      compareCorrelations(
        correlateReports([findingReport("monorepo/main")]),
        correlateReports([findingReport("monorepo/release")]),
      ),
      "csv",
    );
    expect(csv).toContain("SARIF automation categories");
    expect(csv).toContain("monorepo/main");
    expect(csv).toContain("monorepo/release");
  });

  it("distinguishes updated evidence from findings absent in the current run", () => {
    const baseline = correlateReports([report("trivy.json"), report("grype.json")]);
    const current = correlateReports([report("trivy.json")]);
    const diff = compareCorrelations(baseline, current);
    expect(diff.summary).toMatchObject({ new: 0, updated: 1, absent: 1, unchanged: 1 });
    expect(diff.scanSetChange).toMatchObject({
      detected: true,
      addedTools: [],
      removedTools: ["Grype"],
    });
    expect(diff.items.find((item) => item.state === "updated")?.changedFields).toEqual(
      expect.arrayContaining(["source-tools", "source-records"]),
    );
  });

  it("exports baseline states in SARIF, Markdown, CSV, and portable HTML", () => {
    const baseline = correlateReports([report("trivy.json")]);
    const current = correlateReports([report("trivy.json"), report("generic.csv")]);
    const diff = compareCorrelations(baseline, current);
    const sarif = JSON.parse(exportBaselineDiff(diff, "sarif")) as {
      runs: Array<{
        invocations: Array<{ properties?: { scanSetChange?: { detected?: boolean } } }>;
        results: Array<{ baselineState?: string; partialFingerprints?: unknown }>;
      }>;
    };
    expect(sarif.runs[0]?.results.every((result) => result.baselineState)).toBe(true);
    expect(sarif.runs[0]?.results.every((result) => result.partialFingerprints)).toBe(true);
    expect(sarif.runs[0]?.invocations[0]?.properties?.scanSetChange?.detected).toBe(true);
    const markdown = exportBaselineDiff(diff, "markdown");
    expect(markdown).toContain("VulnFuse baseline comparison");
    expect(markdown).toContain("Scan set changed");
    expect(markdown).toContain("## Current-run scanner coverage");
    expect(exportBaselineDiff(diff, "csv")).toContain("scan_set_changed");
    const html = exportBaselineDiff(diff, "html");
    expect(html).toContain('id="state-filter"');
    expect(html).toContain('data-state="new"');
    expect(html).toContain("Scan set changed");
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

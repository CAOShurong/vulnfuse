import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  compareCorrelations,
  correlateReports,
  explainMatch,
  exportBaselineDiff,
  exportCorrelation,
  parseReport,
  type CanonicalFinding,
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

  it("produces stable cluster IDs", () => {
    const reports = [report("trivy.json"), report("grype.json")];
    expect(correlateReports(reports).clusters.map((cluster) => cluster.id)).toEqual(
      correlateReports(reports).clusters.map((cluster) => cluster.id),
    );
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
    expect(exportCorrelation(result, "markdown")).toContain("Why merged");
    expect(exportCorrelation(result, "csv")).toContain("duplicates_collapsed");
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

  it("exports baseline states in SARIF, Markdown, and CSV", () => {
    const baseline = correlateReports([report("trivy.json")]);
    const current = correlateReports([report("trivy.json"), report("generic.csv")]);
    const diff = compareCorrelations(baseline, current);
    const sarif = JSON.parse(exportBaselineDiff(diff, "sarif")) as {
      runs: Array<{ results: Array<{ baselineState?: string; partialFingerprints?: unknown }> }>;
    };
    expect(sarif.runs[0]?.results.every((result) => result.baselineState)).toBe(true);
    expect(sarif.runs[0]?.results.every((result) => result.partialFingerprints)).toBe(true);
    expect(exportBaselineDiff(diff, "markdown")).toContain("VulnFuse baseline comparison");
    expect(exportBaselineDiff(diff, "csv")).toContain("baseline_state");
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

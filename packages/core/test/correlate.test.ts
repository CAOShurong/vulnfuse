import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  correlateReports,
  explainMatch,
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

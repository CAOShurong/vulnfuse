import { describe, expect, it } from "vitest";

import { compareCorrelations, correlateReports, parseReport } from "@vulnfuse/core";

import { demoBaselineReports, demoReports } from "./demo.js";

describe("safe browser demo", () => {
  it("demonstrates both instance and root-cause correlation", () => {
    const reports = demoReports.map((input) => parseReport(input));
    const instance = correlateReports(reports, { scope: "instance" });
    const rootCause = correlateReports(reports, { scope: "root-cause" });
    expect(instance.summary.inputFindings).toBe(5);
    expect(instance.summary.duplicatesCollapsed).toBe(1);
    expect(instance.summary).toMatchObject({
      activeClusters: 4,
      suppressedClusters: 0,
      nonFindingClusters: 0,
    });
    expect(instance.summary.coverage).toMatchObject({
      singleToolClusters: 3,
      multiToolClusters: 1,
    });
    expect(
      instance.summary.coverage.pairs.find(
        (pair) => pair.leftTool === "Grype" && pair.rightTool === "Trivy",
      ),
    ).toMatchObject({ sharedClusters: 1, unionClusters: 3, overlapRatio: 0.3333 });
    expect(rootCause.summary.duplicatesCollapsed).toBe(2);
  });

  it("supports a local baseline comparison without uploading reports", () => {
    const reports = demoReports.map((input) => parseReport(input));
    const baseline = correlateReports(
      demoBaselineReports.map((input) => parseReport(input)),
      {
        scope: "instance",
      },
    );
    const current = correlateReports(reports, { scope: "instance" });
    const diff = compareCorrelations(baseline, current);
    expect(diff.summary).toMatchObject({
      new: 2,
      updated: 1,
      unchanged: 1,
      absent: 0,
    });
    expect(diff.scanSetChange).toMatchObject({
      detected: true,
      addedTools: ["Grype", "Snyk"],
      removedTools: [],
    });
  });
});

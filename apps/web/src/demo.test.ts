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
    expect(compareCorrelations(baseline, current).summary).toMatchObject({
      new: 2,
      updated: 1,
      unchanged: 1,
      absent: 0,
    });
  });
});

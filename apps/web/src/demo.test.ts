import { describe, expect, it } from "vitest";

import { correlateReports, parseReport } from "@vulnfuse/core";

import { demoReports } from "./demo.js";

describe("safe browser demo", () => {
  it("demonstrates both instance and root-cause correlation", () => {
    const reports = demoReports.map((input) => parseReport(input));
    const instance = correlateReports(reports, { scope: "instance" });
    const rootCause = correlateReports(reports, { scope: "root-cause" });
    expect(instance.summary.inputFindings).toBe(5);
    expect(instance.summary.duplicatesCollapsed).toBe(1);
    expect(rootCause.summary.duplicatesCollapsed).toBe(2);
  });
});

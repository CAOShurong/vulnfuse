import { describe, expect, it } from "vitest";

import { shouldShowAnalysisResults } from "./App.js";

describe("analysis result visibility", () => {
  it("keeps baseline warnings and exports visible for zero-finding reports", () => {
    expect(shouldShowAnalysisResults(1)).toBe(true);
    expect(shouldShowAnalysisResults(0)).toBe(false);
  });
});

import { describe, expect, it } from "vitest";

import {
  extractIdentifiers,
  normalizeIdentifier,
  normalizePath,
  normalizeSeverity,
  stableHash,
} from "../src/index.js";

describe("normalization helpers", () => {
  it("extracts common advisory identifiers", () => {
    expect(
      extractIdentifiers(["CVE-2024-12345 / GHSA-jfh8-c2jp-5v3q and CWE-79"]).map(
        (item) => item.scheme,
      ),
    ).toEqual(expect.arrayContaining(["CVE", "GHSA", "CWE"]));
  });

  it("normalizes paths and severity values", () => {
    expect(normalizeIdentifier("CVE-2024-12345).;:")?.value).toBe("CVE-2024-12345");
    expect(normalizePath("file:///C:/Repo/src\\index.ts?x=1")).toBe("c:/repo/src/index.ts");
    expect(normalizeSeverity("9.8")).toBe("critical");
    expect(normalizeSeverity("moderate")).toBe("medium");
  });

  it("hashes deterministically", () => {
    expect(stableHash("same")).toBe(stableHash("same"));
    expect(stableHash("same")).not.toBe(stableHash("different"));
  });
});

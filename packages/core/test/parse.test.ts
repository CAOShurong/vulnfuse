import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { detectFormat, parseReport } from "../src/index.js";

function fixture(name: string): string {
  return readFileSync(fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)), "utf8");
}

describe("report parsing", () => {
  const cases = [
    ["trivy.json", "trivy", "Trivy", 2],
    ["grype.json", "grype", "Grype", 2],
    ["snyk.json", "snyk", "Snyk", 1],
    ["osv.json", "osv-scanner", "OSV-Scanner", 1],
    ["cyclonedx.json", "cyclonedx", "Syft", 1],
    ["sarif.json", "sarif", "CodeQL", 1],
    ["generic.csv", "csv", "Legacy Scanner", 1],
  ] as const;

  it.each(cases)("detects and parses %s", (name, format, tool, count) => {
    const content = fixture(name);
    expect(detectFormat(content, name)).toBe(format);
    const report = parseReport({ name, content });
    expect(report.format).toBe(format);
    expect(report.tool).toBe(tool);
    expect(report.findings).toHaveLength(count);
    expect(report.findings.every((finding) => finding.id.startsWith("finding-"))).toBe(true);
  });

  it("normalizes remediation and identifiers", () => {
    const report = parseReport({ name: "osv.json", content: fixture("osv.json") });
    const finding = report.findings[0];
    expect(finding?.identifiers.map((identifier) => identifier.value)).toEqual(
      expect.arrayContaining(["CVE-2021-44228", "GHSA-JFH8-C2JP-5V3Q"]),
    );
    expect(finding?.component?.purl).toBe("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
    expect(finding?.remediation?.fixedVersion).toBe("2.17.1");
  });

  it("rejects unknown documents and oversized inputs", () => {
    expect(() => parseReport({ name: "mystery.json", content: '{"hello":"world"}' })).toThrow(
      /Could not detect/,
    );
    expect(detectFormat("not a report", "stdin")).toBe("unknown");
    expect(detectFormat("\u0000binary,data\nvalue,other", "stdin")).toBe("unknown");
    expect(() =>
      parseReport({ name: "large.csv", content: "title\nabc" }, { maxBytes: 4 }),
    ).toThrow(/configured limit/);
  });
});

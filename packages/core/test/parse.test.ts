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

  it("keeps scanner versions separate from report schema versions", () => {
    const cyclonedx = parseReport({ name: "cyclonedx.json", content: fixture("cyclonedx.json") });
    expect(cyclonedx.findings[0]?.source.version).toBe("1.0.0");
    expect(cyclonedx.metadata["specVersion"]).toBe("1.6");

    const trivyDocument = JSON.parse(fixture("trivy.json")) as Record<string, unknown>;
    trivyDocument["Trivy"] = { Version: "0.66.0" };
    const trivy = parseReport({
      name: "trivy-modern.json",
      content: JSON.stringify(trivyDocument),
    });
    expect(trivy.findings.every((finding) => finding.source.version === "0.66.0")).toBe(true);
    expect(trivy.metadata["schemaVersion"]).toBe("2");

    const legacyTrivy = parseReport({ name: "trivy.json", content: fixture("trivy.json") });
    expect(legacyTrivy.findings.every((finding) => finding.source.version === undefined)).toBe(
      true,
    );
  });

  it("accepts a UTF-8 BOM before JSON input", () => {
    const content = `\uFEFF${fixture("sarif.json")}`;
    expect(detectFormat(content, "stdin")).toBe("sarif");
    const report = parseReport({ name: "stdin", content });
    expect(report.format).toBe("sarif");
    expect(report.tool).toBe("CodeQL");
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

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import { z } from "zod";

import {
  correlateReports,
  countIncompleteReports,
  detectFormat,
  isIncompleteReportWarning,
  parseReport,
} from "../src/index.js";

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
    ["openvex.json", "openvex", "OpenVEX (Example VEX Producer)", 3],
    ["sarif.json", "sarif", "CodeQL", 1],
    ["generic.csv", "csv", "Legacy Scanner", 1],
  ] as const;

  it("disables Zod JIT for strict browser content security policies", () => {
    expect(z.config().jitless).toBe(true);
  });

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

  it("expands every CycloneDX affect and recovers valid PURLs from BOM-Link fragments", () => {
    const parsed = parseReport({
      name: "external-vex.json",
      content: fixture("cyclonedx-bomlink.json"),
    });

    expect(parsed.findings).toHaveLength(2);
    expect(parsed.findings[0]).toMatchObject({
      title:
        "CVE-2018-7489 in pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.0?type=jar",
      component: {
        purl: "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.0?type=jar",
        version: "2.10.0",
      },
    });
    expect(parsed.findings[1]?.component).toEqual({ version: "vers:generic/>=4.5|<5.0" });
    expect(parsed.findings[0]?.id).not.toBe(parsed.findings[1]?.id);
  });

  it("expands OpenVEX products and subcomponents without trusting producer status", () => {
    const parsed = parseReport({ name: "openvex.json", content: fixture("openvex.json") });

    expect(parsed.findings).toHaveLength(3);
    expect(parsed.findings.map((finding) => finding.component?.purl)).toEqual([
      "pkg:apk/alpine/git@2.45.2-r0?arch=x86_64",
      "pkg:apk/alpine/curl@8.9.0-r0?arch=x86_64",
      "pkg:npm/lodash@4.17.20",
    ]);
    expect(parsed.findings[0]).toMatchObject({
      kind: "sca",
      asset: {
        type: "image",
        name: "pkg:oci/widget@sha256:1111111111111111111111111111111111111111111111111111111111111111",
      },
      suppressed: false,
      nonFinding: false,
      properties: {
        "openvex.status": "not_affected",
        "openvex.justification": "vulnerable_code_not_in_execute_path",
      },
    });
    expect(parsed.findings[0]?.identifiers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ value: "CVE-2024-32002", relationship: "primary" }),
        expect.objectContaining({ value: "GHSA-8R3F-844C-MC37", relationship: "alias" }),
      ]),
    );
  });

  it("warns and keeps malformed OpenVEX assertions active", () => {
    const parsed = parseReport({
      name: "malformed.openvex.json",
      content: JSON.stringify({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://example.test/vex/malformed",
        author: "Unverified Producer",
        timestamp: "2026-08-11T00:00:00Z",
        version: 1,
        statements: [
          {
            vulnerability: { name: "CVE-2024-0001" },
            products: [{ "@id": "pkg:npm/example@1.0.0" }],
            status: "accepted_risk",
          },
          {
            vulnerability: { name: "CVE-2024-0002" },
            products: [{ "@id": "https://example.test/product", identifiers: { purl: "bad" } }],
            status: "not_affected",
          },
          {
            vulnerability: { name: "CVE-2024-0003" },
            status: "affected",
          },
        ],
      }),
    });

    expect(parsed.findings).toHaveLength(2);
    expect(parsed.findings.every((finding) => !finding.suppressed && !finding.nonFinding)).toBe(
      true,
    );
    expect(parsed.findings[1]?.component).toBeUndefined();
    expect(parsed.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: "openvex.invalid-status", path: "statements[0].status" }),
        expect.objectContaining({
          code: "openvex.invalid-purl",
          path: "statements[1].products[0].identifiers.purl",
        }),
        expect.objectContaining({
          code: "openvex.incomplete-not-affected",
          path: "statements[1]",
        }),
        expect.objectContaining({ code: "openvex.no-products", path: "statements[2].products" }),
      ]),
    );
  });

  it("does not guess a package identity from an arbitrary external BOM reference", () => {
    const parsed = parseReport({
      name: "external-vex.json",
      content: fixture("cyclonedx-bomlink.json"),
    });

    expect(parsed.findings[1]?.component?.purl).toBeUndefined();
    expect(parsed.findings[1]?.title).toContain("#product-JKL");
  });

  it("preserves SARIF suppression evidence and evaluates it conservatively", () => {
    const document = JSON.parse(fixture("sarif-suppressed.json")) as {
      runs: Array<{ results: Array<Record<string, unknown>> }>;
    };
    const template = document.runs[0]?.results[0];
    expect(template).toBeDefined();
    if (!template || !document.runs[0]) return;
    document.runs[0].results = [
      { ...template, guid: "missing-status" },
      {
        ...template,
        guid: "accepted",
        suppressions: [{ kind: "external", status: "accepted", justification: "reviewed" }],
      },
      {
        ...template,
        guid: "under-review",
        suppressions: [{ kind: "external", status: "underReview" }],
      },
      {
        ...template,
        guid: "rejected",
        suppressions: [{ kind: "external", status: "rejected" }],
      },
      {
        ...template,
        guid: "unknown-status",
        suppressions: [{ kind: "external", status: "invented", justification: "untrusted" }],
      },
    ];

    const parsed = parseReport({
      name: "suppression-cases.sarif",
      content: JSON.stringify(document),
    });
    expect(parsed.findings.map((finding) => finding.suppressed)).toEqual([
      true,
      true,
      false,
      false,
      false,
    ]);
    expect(parsed.findings[0]?.suppressions?.[0]).toMatchObject({
      kind: "inSource",
      justification: "Reviewed <script>alert('not markup')</script>",
    });
    expect(parsed.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "sarif.invalid-suppression",
          path: "runs[0].results[4].suppressions[0]",
        }),
      ]),
    );
  });

  it("uses portable SARIF URI-base prefixes to correlate repository-relative locations", () => {
    const parsed = parseReport({
      name: "sarif-uri-bases.json",
      content: fixture("sarif-uri-bases.json"),
    });

    expect(parsed.findings).toHaveLength(2);
    expect(parsed.findings.map((finding) => finding.location?.uri)).toEqual([
      "src/lib/memory.c",
      "src/lib/memory.c",
    ]);
    expect(parsed.findings[0]?.properties).toMatchObject({
      "sarif.originalLocationUri": "lib/memory.c",
      "sarif.locationUriBaseId": "SRCROOT",
      "sarif.locationResolution": "redacted-root",
    });
    expect(parsed.warnings).toEqual([]);

    const correlated = correlateReports([parsed]);
    expect(correlated.summary).toMatchObject({
      inputFindings: 2,
      clusters: 1,
      duplicatesCollapsed: 1,
    });
    expect(correlated.clusters[0]?.sourceTools).toEqual([
      "Relative Path Scanner",
      "Repository Path Scanner",
    ]);
  });

  it("keeps raw SARIF locations and warns for unknown, circular, and invalid URI bases", () => {
    const parsed = parseReport({
      name: "malformed-uri-bases.sarif",
      content: fixture("sarif-uri-bases-malformed.json"),
    });

    expect(parsed.findings.map((finding) => finding.location?.uri)).toEqual([
      "unknown.c",
      "cycle.c",
      "invalid.c",
      "src/portable.c",
    ]);
    expect(parsed.findings[3]?.properties).toMatchObject({
      "sarif.originalLocationUri": "portable.c",
      "sarif.locationUriBaseId": "ABSSRC",
      "sarif.locationResolution": "absolute-root-omitted",
    });
    expect(parsed.findings[3]?.location?.uri).not.toContain("Users");
    expect(parsed.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "sarif.unknown-uri-base",
          path: "runs[0].results[0].locations[0].physicalLocation.artifactLocation.uriBaseId",
        }),
        expect.objectContaining({
          code: "sarif.circular-uri-base",
          path: "runs[0].results[1].locations[0].physicalLocation.artifactLocation.uriBaseId",
        }),
        expect.objectContaining({
          code: "sarif.invalid-uri-base",
          path: "runs[0].originalUriBaseIds.BAD.uri",
        }),
      ]),
    );
  });

  it("retains partial SARIF findings while surfacing every run-completeness signal", () => {
    const parsed = parseReport({
      name: "sarif-incomplete.json",
      content: fixture("sarif-incomplete.json"),
    });

    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]?.title).toBe("Partial evidence must be retained.");
    expect(parsed.warnings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: "sarif.execution-failed",
          path: "runs[0].invocations[0].executionSuccessful",
        }),
        expect.objectContaining({
          code: "sarif.tool-execution-error",
          path: "runs[0].invocations[0].toolExecutionNotifications[0]",
        }),
        expect.objectContaining({
          code: "sarif.tool-configuration-error",
          path: "runs[0].invocations[0].toolConfigurationNotifications[0]",
        }),
        expect.objectContaining({
          code: "sarif.invalid-invocation",
          path: "runs[0].invocations[1]",
        }),
        expect.objectContaining({
          code: "sarif.execution-status-unknown",
          path: "runs[0].invocations[2].executionSuccessful",
        }),
      ]),
    );
    expect(parsed.warnings.filter(isIncompleteReportWarning)).toHaveLength(5);
    expect(countIncompleteReports([parsed])).toBe(1);
  });

  it("warns when SARIF results are unavailable or externally referenced", () => {
    const unavailable = parseReport({
      name: "unavailable.sarif",
      content: JSON.stringify({
        version: "2.1.0",
        runs: [{ tool: { driver: { name: "Unavailable Scanner" } } }],
      }),
    });
    const external = parseReport({
      name: "external.sarif",
      content: JSON.stringify({
        version: "2.1.0",
        runs: [
          {
            tool: { driver: { name: "External Scanner" } },
            externalPropertyFileReferences: {
              results: [{ location: { uri: "results.sarif-external-properties" } }],
            },
          },
        ],
      }),
    });

    expect(unavailable.warnings).toContainEqual(
      expect.objectContaining({ code: "sarif.results-unavailable", path: "runs[0].results" }),
    );
    expect(external.warnings).toContainEqual(
      expect.objectContaining({
        code: "sarif.external-results-unsupported",
        path: "runs[0].externalPropertyFileReferences.results",
      }),
    );
    expect(countIncompleteReports([unavailable, external])).toBe(2);
  });

  it("keeps non-problem SARIF result kinds as evidence without treating them as findings", () => {
    const parsed = parseReport({
      name: "result-kinds.sarif",
      content: fixture("sarif-result-kinds.json"),
    });

    expect(parsed.findings.map((finding) => finding.nonFinding)).toEqual([
      true,
      true,
      true,
      false,
      false,
      false,
      false,
      false,
      false,
      false,
    ]);
    expect(parsed.findings.map((finding) => finding.properties["sarif.resultKind"])).toEqual([
      "pass",
      "informational",
      "notApplicable",
      "open",
      "review",
      "fail",
      "fail",
      "invented",
      42,
      "pass",
    ]);
    expect(parsed.warnings).toEqual([
      expect.objectContaining({
        code: "sarif.invalid-result-kind",
        path: "runs[0].results[7].kind",
      }),
      expect.objectContaining({
        code: "sarif.invalid-result-kind",
        path: "runs[0].results[8].kind",
      }),
      expect.objectContaining({
        code: "sarif.inconsistent-result-kind",
        path: "runs[0].results[9].kind",
      }),
    ]);
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

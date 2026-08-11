import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

const execute = promisify(execFile);
const action = resolve(import.meta.dirname, "../dist/index.cjs");
const repository = resolve(import.meta.dirname, "../../..");
const trivy = resolve(repository, "packages/core/test/fixtures/trivy.json");
const grype = resolve(repository, "packages/core/test/fixtures/grype.json");
const csv = resolve(repository, "packages/core/test/fixtures/generic.csv");
const openVex = resolve(repository, "packages/core/test/fixtures/openvex.json");
const cycloneXml = resolve(repository, "packages/core/test/fixtures/cyclonedx-vex.xml");
const suppressedSarif = resolve(repository, "packages/core/test/fixtures/sarif-suppressed.json");
const resultKindsSarif = resolve(repository, "packages/core/test/fixtures/sarif-result-kinds.json");
const incompleteSarif = resolve(repository, "packages/core/test/fixtures/sarif-incomplete.json");
const uriBaseSarif = resolve(repository, "packages/core/test/fixtures/sarif-uri-bases.json");
const malformedUriBaseSarif = resolve(
  repository,
  "packages/core/test/fixtures/sarif-uri-bases-malformed.json",
);
let testDirectory: string;

beforeEach(async () => {
  testDirectory = await mkdtemp(join(tmpdir(), "vulnfuse-action-"));
});

afterEach(async () => {
  await rm(testDirectory, { recursive: true, force: true });
});

describe("GitHub Action bundle", () => {
  it("processes CycloneDX XML VEX through the committed Action bundle", async () => {
    const outputReport = join(testDirectory, "cyclonedx-xml.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await execute(process.execPath, [action], {
      cwd: repository,
      env: {
        ...process.env,
        INPUT_REPORTS: cycloneXml,
        INPUT_OUTPUT: outputReport,
        INPUT_FORMAT: "json",
        GITHUB_OUTPUT: githubOutput,
        GITHUB_STEP_SUMMARY: stepSummary,
        GITHUB_WORKSPACE: repository,
        RUNNER_TEMP: testDirectory,
      },
    });

    const result = JSON.parse(await readFile(outputReport, "utf8")) as {
      summary: { inputFindings: number; clusters: number };
      clusters: Array<{ primary: { component?: { purl?: string } } }>;
    };
    expect(result.summary).toMatchObject({ inputFindings: 1, clusters: 1 });
    expect(result.clusters[0]?.primary.component?.purl).toBe(
      "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.4",
    );
    expect(await readFile(githubOutput, "utf8")).toContain("findings");
    expect(await readFile(stepSummary, "utf8")).toContain("CycloneDX");
  });

  it("correlates portable SARIF URI-base paths through the committed Action bundle", async () => {
    const outputReport = join(testDirectory, "uri-base.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await execute(process.execPath, [action], {
      cwd: repository,
      env: {
        ...process.env,
        INPUT_REPORTS: uriBaseSarif,
        INPUT_OUTPUT: outputReport,
        INPUT_FORMAT: "json",
        GITHUB_OUTPUT: githubOutput,
        GITHUB_STEP_SUMMARY: stepSummary,
        GITHUB_WORKSPACE: repository,
        RUNNER_TEMP: testDirectory,
      },
    });

    const result = JSON.parse(await readFile(outputReport, "utf8")) as {
      summary: { inputFindings: number; clusters: number; duplicatesCollapsed: number };
      clusters: Array<{ primary: { location?: { uri?: string } } }>;
    };
    expect(result.summary).toMatchObject({ inputFindings: 2, clusters: 1, duplicatesCollapsed: 1 });
    expect(result.clusters[0]?.primary.location?.uri).toBe("src/lib/memory.c");
    expect(await readFile(githubOutput, "utf8")).toContain("duplicates-collapsed");
    expect(await readFile(stepSummary, "utf8")).toContain("Relative Path Scanner");
    expect(await readFile(stepSummary, "utf8")).toContain("Repository Path Scanner");
  });

  it("emits annotations while preserving malformed SARIF URI-base findings", async () => {
    const outputReport = join(testDirectory, "malformed-uri-base.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    const execution = await execute(process.execPath, [action], {
      cwd: repository,
      env: {
        ...process.env,
        INPUT_REPORTS: malformedUriBaseSarif,
        INPUT_OUTPUT: outputReport,
        INPUT_FORMAT: "json",
        GITHUB_OUTPUT: githubOutput,
        GITHUB_STEP_SUMMARY: stepSummary,
        GITHUB_WORKSPACE: repository,
        RUNNER_TEMP: testDirectory,
      },
    });

    const result = JSON.parse(await readFile(outputReport, "utf8")) as {
      summary: { inputFindings: number };
      reports: Array<{ warnings: Array<{ code: string }> }>;
    };
    expect(result.summary.inputFindings).toBe(4);
    expect(result.reports[0]?.warnings).toHaveLength(3);
    expect(execution.stdout).toContain("::warning");
    expect(execution.stdout).toContain("sarif.unknown-uri-base");
    expect(execution.stdout).toContain("sarif.circular-uri-base");
    expect(execution.stdout).toContain("sarif.invalid-uri-base");
  });

  it("writes partial SARIF evidence and outputs before failing the incomplete-run gate", async () => {
    const outputReport = join(testDirectory, "partial.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await expect(
      execute(process.execPath, [action], {
        cwd: repository,
        env: {
          ...process.env,
          INPUT_REPORTS: incompleteSarif,
          INPUT_OUTPUT: outputReport,
          INPUT_FORMAT: "json",
          "INPUT_FAIL-ON-INCOMPLETE": "true",
          GITHUB_OUTPUT: githubOutput,
          GITHUB_STEP_SUMMARY: stepSummary,
          GITHUB_WORKSPACE: repository,
          RUNNER_TEMP: testDirectory,
        },
      }),
    ).rejects.toMatchObject({ code: 1 });

    const result = JSON.parse(await readFile(outputReport, "utf8")) as {
      summary: { inputFindings: number };
      reports: Array<{ warnings: Array<{ code: string }> }>;
    };
    expect(result.summary.inputFindings).toBe(1);
    expect(result.reports[0]?.warnings).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "sarif.execution-failed" })]),
    );
    expect(await readFile(githubOutput, "utf8")).toContain("incomplete-reports");
    expect(await readFile(stepSummary, "utf8")).toContain("Incomplete input reports");
  });

  it("correlates OpenVEX evidence without applying producer status as a gate verdict", async () => {
    const scanner = join(testDirectory, "scanner.csv");
    const outputReport = join(testDirectory, "openvex-report.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(
      scanner,
      "vulnerability_id,title,severity,purl,tool\n" +
        'CVE-2024-32002,"CVE-2024-32002 for pkg:apk/alpine/git@2.45.2-r0?arch=x86_64 (OpenVEX: not_affected)",high,"pkg:apk/alpine/git@2.45.2-r0?arch=x86_64",Other Scanner\n',
      "utf8",
    );
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await execute(process.execPath, [action], {
      cwd: repository,
      env: {
        ...process.env,
        INPUT_REPORTS: `${openVex}\n${scanner}`,
        INPUT_OUTPUT: outputReport,
        INPUT_FORMAT: "json",
        INPUT_SCOPE: "root-cause",
        GITHUB_OUTPUT: githubOutput,
        GITHUB_STEP_SUMMARY: stepSummary,
        GITHUB_WORKSPACE: repository,
        RUNNER_TEMP: testDirectory,
      },
    });

    const result = JSON.parse(await readFile(outputReport, "utf8")) as {
      summary: {
        inputFindings: number;
        clusters: number;
        duplicatesCollapsed: number;
        activeClusters: number;
      };
      clusters: Array<{ sourceTools: string[]; suppressed: boolean; nonFinding: boolean }>;
    };
    expect(result.summary).toMatchObject({
      inputFindings: 4,
      clusters: 3,
      duplicatesCollapsed: 1,
      activeClusters: 3,
    });
    expect(result.clusters.some((cluster) => cluster.sourceTools.length === 2)).toBe(true);
    expect(result.clusters.every((cluster) => !cluster.suppressed && !cluster.nonFinding)).toBe(
      true,
    );
    expect(await readFile(stepSummary, "utf8")).toContain("OpenVEX (Example VEX Producer)");
  });

  it("runs outside GitHub and writes report, outputs, and summary", async () => {
    const outputReport = join(testDirectory, "report.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await execute(process.execPath, [action], {
      cwd: repository,
      env: {
        ...process.env,
        INPUT_REPORTS: `${trivy}\n${grype}`,
        INPUT_OUTPUT: outputReport,
        INPUT_FORMAT: "json",
        INPUT_THRESHOLD: "70",
        INPUT_SCOPE: "instance",
        GITHUB_OUTPUT: githubOutput,
        GITHUB_STEP_SUMMARY: stepSummary,
        GITHUB_WORKSPACE: repository,
        RUNNER_TEMP: testDirectory,
      },
    });

    const result = JSON.parse(await readFile(outputReport, "utf8")) as {
      summary: { inputFindings: number; clusters: number; duplicatesCollapsed: number };
    };
    expect(result.summary).toMatchObject({ inputFindings: 4, clusters: 3, duplicatesCollapsed: 1 });
    const outputs = await readFile(githubOutput, "utf8");
    const summary = await readFile(stepSummary, "utf8");
    expect(outputs).toContain("duplicates-collapsed");
    expect(outputs).toContain("single-tool");
    expect(outputs).toContain("multi-tool");
    expect(summary).toContain("VulnFuse correlation");
    expect(summary).toContain("Scanner coverage");
    expect(summary).toContain("Grype / Trivy");
  });

  it("writes a baseline diff before failing on a new high-severity cluster", async () => {
    const outputReport = join(testDirectory, "baseline.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await expect(
      execute(process.execPath, [action], {
        cwd: repository,
        env: {
          ...process.env,
          INPUT_REPORTS: `${trivy}\n${csv}`,
          "INPUT_BASELINE-REPORTS": trivy,
          INPUT_OUTPUT: outputReport,
          INPUT_FORMAT: "json",
          INPUT_THRESHOLD: "70",
          INPUT_SCOPE: "instance",
          "INPUT_FAIL-ON-NEW": "high",
          GITHUB_OUTPUT: githubOutput,
          GITHUB_STEP_SUMMARY: stepSummary,
          GITHUB_WORKSPACE: repository,
          RUNNER_TEMP: testDirectory,
        },
      }),
    ).rejects.toMatchObject({ code: 1 });

    const diff = JSON.parse(await readFile(outputReport, "utf8")) as {
      summary: { new: number; unchanged: number };
    };
    expect(diff.summary).toMatchObject({ new: 1, unchanged: 2 });
    expect(await readFile(githubOutput, "utf8")).toContain("new<<");
    expect(await readFile(stepSummary, "utf8")).toContain("Baseline:");
  });

  it("keeps suppressed SARIF evidence without failing the active severity gate", async () => {
    const outputReport = join(testDirectory, "suppressed.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await execute(process.execPath, [action], {
      cwd: repository,
      env: {
        ...process.env,
        INPUT_REPORTS: suppressedSarif,
        INPUT_OUTPUT: outputReport,
        INPUT_FORMAT: "json",
        "INPUT_FAIL-ON": "high",
        GITHUB_OUTPUT: githubOutput,
        GITHUB_STEP_SUMMARY: stepSummary,
        GITHUB_WORKSPACE: repository,
        RUNNER_TEMP: testDirectory,
      },
    });

    const result = JSON.parse(await readFile(outputReport, "utf8")) as {
      summary: { activeClusters: number; suppressedClusters: number };
    };
    expect(result.summary).toMatchObject({ activeClusters: 0, suppressedClusters: 2 });
    expect(await readFile(githubOutput, "utf8")).toContain("suppressed");
    expect(await readFile(stepSummary, "utf8")).toContain("suppressed");
  });

  it("retains non-finding SARIF evidence without failing or creating hosted SARIF alerts", async () => {
    const document = JSON.parse(await readFile(resultKindsSarif, "utf8")) as {
      runs: Array<{ results: Array<Record<string, unknown>> }>;
    };
    if (!document.runs[0]) return;
    document.runs[0].results = document.runs[0].results.slice(0, 3);
    const input = join(testDirectory, "non-finding-only.sarif");
    const outputReport = join(testDirectory, "non-finding-output.sarif");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(input, JSON.stringify(document), "utf8");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await execute(process.execPath, [action], {
      cwd: repository,
      env: {
        ...process.env,
        INPUT_REPORTS: input,
        INPUT_OUTPUT: outputReport,
        INPUT_FORMAT: "sarif",
        "INPUT_FAIL-ON": "info",
        GITHUB_OUTPUT: githubOutput,
        GITHUB_STEP_SUMMARY: stepSummary,
        GITHUB_WORKSPACE: repository,
        RUNNER_TEMP: testDirectory,
      },
    });

    const sarif = JSON.parse(await readFile(outputReport, "utf8")) as {
      runs: Array<{
        results: unknown[];
        properties?: { nonFindingClusters?: unknown[] };
      }>;
    };
    expect(sarif.runs[0]?.results).toHaveLength(0);
    expect(sarif.runs[0]?.properties?.nonFindingClusters).toHaveLength(3);
    const outputs = await readFile(githubOutput, "utf8");
    expect(outputs).toContain("non-finding");
    expect(await readFile(stepSummary, "utf8")).toContain("Non-finding");
  });

  it("warns and keeps malformed SARIF suppression active", async () => {
    const document = JSON.parse(await readFile(suppressedSarif, "utf8")) as {
      runs: Array<{ results: Array<{ suppressions?: Array<Record<string, unknown>> }> }>;
    };
    const suppression = document.runs[0]?.results[0]?.suppressions?.[0];
    expect(suppression).toBeDefined();
    if (!suppression) return;
    suppression["status"] = "invented";
    const input = join(testDirectory, "malformed-suppression.sarif");
    const outputReport = join(testDirectory, "malformed-suppression.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(input, JSON.stringify(document), "utf8");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    let failure: { code?: number; stdout?: string } | undefined;
    try {
      await execute(process.execPath, [action], {
        cwd: repository,
        env: {
          ...process.env,
          INPUT_REPORTS: input,
          INPUT_OUTPUT: outputReport,
          INPUT_FORMAT: "json",
          "INPUT_FAIL-ON": "high",
          GITHUB_OUTPUT: githubOutput,
          GITHUB_STEP_SUMMARY: stepSummary,
          GITHUB_WORKSPACE: repository,
          RUNNER_TEMP: testDirectory,
        },
      });
    } catch (error) {
      failure = error as { code?: number; stdout?: string };
    }

    expect(failure?.code).toBe(1);
    expect(failure?.stdout).toContain("::warning");
    expect(failure?.stdout).toContain("sarif.invalid-suppression");
    const result = JSON.parse(await readFile(outputReport, "utf8")) as {
      summary: { activeClusters: number; suppressedClusters: number };
    };
    expect(result.summary).toMatchObject({ activeClusters: 1, suppressedClusters: 1 });
  });

  it("writes a baseline diff before failing on a changed scanner set", async () => {
    const outputReport = join(testDirectory, "scan-set-change.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await expect(
      execute(process.execPath, [action], {
        cwd: repository,
        env: {
          ...process.env,
          INPUT_REPORTS: `${trivy}\n${csv}`,
          "INPUT_BASELINE-REPORTS": trivy,
          INPUT_OUTPUT: outputReport,
          INPUT_FORMAT: "json",
          "INPUT_FAIL-ON-SCAN-SET-CHANGE": "true",
          GITHUB_OUTPUT: githubOutput,
          GITHUB_STEP_SUMMARY: stepSummary,
          GITHUB_WORKSPACE: repository,
          RUNNER_TEMP: testDirectory,
        },
      }),
    ).rejects.toMatchObject({ code: 1 });

    const diff = JSON.parse(await readFile(outputReport, "utf8")) as {
      scanSetChange: { detected: boolean; addedTools: string[] };
    };
    expect(diff.scanSetChange).toMatchObject({ detected: true, addedTools: ["Legacy Scanner"] });
    expect(await readFile(githubOutput, "utf8")).toContain("scan-set-changed");
    expect(await readFile(stepSummary, "utf8")).toContain("Scan set changed");
  });

  it("preserves a version-drift diff before the Action fails", async () => {
    const baseline = join(testDirectory, "baseline.sarif");
    const current = join(testDirectory, "current.sarif");
    const outputReport = join(testDirectory, "version-drift.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    const document = {
      version: "2.1.0",
      runs: [{ tool: { driver: { name: "CodeQL", semanticVersion: "2.20.0" } }, results: [] }],
    };
    await writeFile(baseline, JSON.stringify(document), "utf8");
    document.runs[0]!.tool.driver.semanticVersion = "2.26.2";
    await writeFile(current, JSON.stringify(document), "utf8");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await expect(
      execute(process.execPath, [action], {
        cwd: repository,
        env: {
          ...process.env,
          INPUT_REPORTS: current,
          "INPUT_BASELINE-REPORTS": baseline,
          INPUT_OUTPUT: outputReport,
          INPUT_FORMAT: "json",
          "INPUT_FAIL-ON-SCAN-SET-CHANGE": "true",
          GITHUB_OUTPUT: githubOutput,
          GITHUB_STEP_SUMMARY: stepSummary,
          GITHUB_WORKSPACE: repository,
          RUNNER_TEMP: testDirectory,
        },
      }),
    ).rejects.toMatchObject({ code: 1 });

    const diff = JSON.parse(await readFile(outputReport, "utf8")) as {
      scanSetChange: { changedToolVersions: unknown[] };
    };
    expect(diff.scanSetChange.changedToolVersions).toHaveLength(1);
    expect(await readFile(githubOutput, "utf8")).toMatch(
      /scan-set-changed<<[^\r\n]+\r?\ntrue\r?\n/,
    );
    expect(await readFile(stepSummary, "utf8")).toContain(
      'embedded versions "CodeQL" ["2.20.0"] to ["2.26.2"]',
    );
  });

  it("allows the Action to emit a self-contained baseline HTML report", async () => {
    const outputReport = join(testDirectory, "baseline.html");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    const execution = await execute(process.execPath, [action], {
      cwd: repository,
      env: {
        ...process.env,
        INPUT_REPORTS: `${trivy}\n${grype}`,
        "INPUT_BASELINE-REPORTS": trivy,
        INPUT_OUTPUT: outputReport,
        INPUT_FORMAT: "html",
        INPUT_THRESHOLD: "70",
        INPUT_SCOPE: "instance",
        GITHUB_OUTPUT: githubOutput,
        GITHUB_STEP_SUMMARY: stepSummary,
        GITHUB_WORKSPACE: repository,
        RUNNER_TEMP: testDirectory,
      },
    });

    const html = await readFile(outputReport, "utf8");
    expect(html).toContain("VulnFuse baseline comparison");
    expect(html).toContain('id="state-filter"');
    expect(html).toContain("Content-Security-Policy");
    expect(execution.stdout).toContain("::warning");
    expect(execution.stdout).toContain("Scan set changed");
  });

  it("rejects an oversized report without writing output", async () => {
    const oversized = join(testDirectory, "oversized.json");
    const outputReport = join(testDirectory, "oversized-output.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(oversized, "123456", "utf8");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await expect(
      execute(process.execPath, [action], {
        cwd: repository,
        env: {
          ...process.env,
          INPUT_REPORTS: oversized,
          INPUT_OUTPUT: outputReport,
          "INPUT_MAX-BYTES": "5",
          GITHUB_OUTPUT: githubOutput,
          GITHUB_STEP_SUMMARY: stepSummary,
          GITHUB_WORKSPACE: repository,
          RUNNER_TEMP: testDirectory,
        },
      }),
    ).rejects.toMatchObject({ code: 1 });

    await expect(readFile(outputReport, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("preserves a complete report when the replacement write fails partway", async () => {
    const outputReport = join(testDirectory, "report.json");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    const injector = join(testDirectory, "inject-write-failure.cjs");
    const previous = '{"status":"previous-complete-report"}\n';
    await writeFile(outputReport, previous, "utf8");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");
    await writeFile(
      injector,
      `const fs = require("node:fs/promises");
const original = fs.writeFile;
fs.writeFile = async function (path, data, options) {
  if (String(path).startsWith(process.env.VULNFUSE_INJECT_WRITE_PREFIX)) {
    const partial = Buffer.isBuffer(data) ? data.subarray(0, 17) : String(data).slice(0, 17);
    await original.call(this, path, partial, options);
    throw new Error("injected partial write failure");
  }
  return original.apply(this, arguments);
};
`,
      "utf8",
    );

    await expect(
      execute(process.execPath, [action], {
        cwd: repository,
        env: {
          ...process.env,
          INPUT_REPORTS: `${trivy}\n${grype}`,
          INPUT_OUTPUT: outputReport,
          INPUT_FORMAT: "json",
          GITHUB_OUTPUT: githubOutput,
          GITHUB_STEP_SUMMARY: stepSummary,
          GITHUB_WORKSPACE: repository,
          RUNNER_TEMP: testDirectory,
          NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require=${injector}`]
            .filter(Boolean)
            .join(" "),
          VULNFUSE_INJECT_WRITE_PREFIX: outputReport,
        },
      }),
    ).rejects.toMatchObject({ code: 1 });

    expect(await readFile(outputReport, "utf8")).toBe(previous);
    expect((await readdir(testDirectory)).filter((name) => name.includes(".vulnfuse-"))).toEqual(
      [],
    );
  });
});

import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
let testDirectory: string;

beforeEach(async () => {
  testDirectory = await mkdtemp(join(tmpdir(), "vulnfuse-action-"));
});

afterEach(async () => {
  await rm(testDirectory, { recursive: true, force: true });
});

describe("GitHub Action bundle", () => {
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

  it("allows the Action to emit a self-contained baseline HTML report", async () => {
    const outputReport = join(testDirectory, "baseline.html");
    const githubOutput = join(testDirectory, "github-output.txt");
    const stepSummary = join(testDirectory, "summary.md");
    await writeFile(githubOutput, "", "utf8");
    await writeFile(stepSummary, "", "utf8");

    await execute(process.execPath, [action], {
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
  });
});

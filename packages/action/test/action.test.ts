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
    expect(await readFile(githubOutput, "utf8")).toContain("duplicates-collapsed");
    expect(await readFile(stepSummary, "utf8")).toContain("VulnFuse correlation");
  });
});

import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

const execute = promisify(execFile);
const cli = resolve(import.meta.dirname, "../dist/index.js");
const trivy = resolve(import.meta.dirname, "../../core/test/fixtures/trivy.json");
const grype = resolve(import.meta.dirname, "../../core/test/fixtures/grype.json");
const csv = resolve(import.meta.dirname, "../../core/test/fixtures/generic.csv");
let testDirectory: string;

beforeEach(async () => {
  testDirectory = await mkdtemp(join(tmpdir(), "vulnfuse-cli-"));
});

afterEach(async () => {
  await rm(testDirectory, { recursive: true, force: true });
});

describe("CLI", () => {
  it("inspects and correlates reports in a separate process", async () => {
    const inspection = await execute(process.execPath, [cli, "inspect", trivy, grype]);
    expect(inspection.stdout).toContain("Trivy");
    expect(inspection.stdout).toContain("Grype");

    const output = join(testDirectory, "result.json");
    await execute(process.execPath, [
      cli,
      "merge",
      trivy,
      grype,
      "--format",
      "json",
      "--output",
      output,
    ]);
    const result = JSON.parse(await readFile(output, "utf8")) as {
      summary: { inputFindings: number; clusters: number; duplicatesCollapsed: number };
    };
    expect(result.summary).toMatchObject({ inputFindings: 4, clusters: 3, duplicatesCollapsed: 1 });
  });

  it("writes the report before applying the fail-on exit code", async () => {
    const output = join(testDirectory, "blocked.sarif");
    await expect(
      execute(process.execPath, [
        cli,
        "merge",
        trivy,
        grype,
        "--format",
        "sarif",
        "--output",
        output,
        "--fail-on",
        "high",
      ]),
    ).rejects.toMatchObject({ code: 1 });
    const sarif = JSON.parse(await readFile(output, "utf8")) as { version: string };
    expect(sarif.version).toBe("2.1.0");
  });

  it("refuses to overwrite an input report", async () => {
    await expect(
      execute(process.execPath, [cli, "merge", trivy, "--output", trivy]),
    ).rejects.toMatchObject({ code: 1 });
  });

  it("compares a baseline and fails only for a new severe cluster", async () => {
    const output = join(testDirectory, "baseline.md");
    await expect(
      execute(process.execPath, [
        cli,
        "diff",
        "--baseline",
        trivy,
        trivy,
        csv,
        "--format",
        "markdown",
        "--output",
        output,
        "--fail-on-new",
        "high",
      ]),
    ).rejects.toMatchObject({ code: 1 });
    const markdown = await readFile(output, "utf8");
    expect(markdown).toContain("**1 new**");
    expect(markdown).toContain("[NEW]");
  });

  it("writes a portable HTML report from the same CLI workflow", async () => {
    const output = join(testDirectory, "portable.html");
    await execute(process.execPath, [
      cli,
      "merge",
      trivy,
      grype,
      "--format",
      "html",
      "--output",
      output,
    ]);
    const html = await readFile(output, "utf8");
    expect(html).toContain("<!doctype html>");
    expect(html).toContain('id="asset-filter"');
    expect(html).toContain("This self-contained file makes no network requests.");
  });
});

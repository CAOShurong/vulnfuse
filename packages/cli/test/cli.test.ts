import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
      summary: {
        inputFindings: number;
        clusters: number;
        duplicatesCollapsed: number;
        coverage: { singleToolClusters: number; multiToolClusters: number };
      };
    };
    expect(result.summary).toMatchObject({ inputFindings: 4, clusters: 3, duplicatesCollapsed: 1 });
    expect(result.summary.coverage).toEqual({
      singleToolClusters: 2,
      multiToolClusters: 1,
      tools: expect.any(Array),
      pairs: expect.any(Array),
      pairwiseOmitted: false,
    });
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

  it("prints one concise diagnostic for a missing input by default", async () => {
    const missing = join(testDirectory, "missing.json");
    const failure = await executeFailure([cli, "merge", missing]);

    expect(failure).toMatchObject({ code: 1, stdout: "" });
    expect(failure.stderr).toMatch(/^vulnfuse: ENOENT: .+missing\.json.+\n$/);
    expect(failure.stderr).not.toContain("node:internal");
    expect(failure.stderr).not.toMatch(/\n\s+at /);
  });

  it("shows the runtime stack only when --debug is requested", async () => {
    const missing = join(testDirectory, "missing.json");
    const failure = await executeFailure([cli, "--debug", "merge", missing]);

    expect(failure).toMatchObject({ code: 1, stdout: "" });
    expect(failure.stderr).toContain("ENOENT");
    expect(failure.stderr).toContain("node:internal");
    expect(failure.stderr).toMatch(/\n\s+at /);
  });

  it("keeps malformed-report diagnostics concise", async () => {
    const malformed = join(testDirectory, "malformed.json");
    await writeFile(malformed, "{not-json", "utf8");
    const failure = await executeFailure([cli, "inspect", malformed]);

    expect(failure).toMatchObject({ code: 1, stdout: "" });
    expect(failure.stderr).toMatch(/^vulnfuse: .+\n$/s);
    expect(failure.stderr).not.toContain("node:internal");
    expect(failure.stderr).not.toMatch(/\n\s+at /);
  });

  it("rejects an oversized report without writing output", async () => {
    const oversized = join(testDirectory, "oversized.json");
    const output = join(testDirectory, "oversized-output.json");
    await writeFile(oversized, "123456", "utf8");
    const failure = await executeFailure([
      cli,
      "merge",
      oversized,
      "--max-bytes",
      "5",
      "--output",
      output,
    ]);

    expect(failure).toMatchObject({ code: 1, stdout: "" });
    expect(failure.stderr).toContain("is 6 bytes; the configured limit is 5 bytes");
    await expect(readFile(output, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
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

  it("writes the diff before failing on a changed scanner set", async () => {
    const output = join(testDirectory, "scan-set-change.json");
    const failure = await executeFailure([
      cli,
      "diff",
      "--baseline",
      trivy,
      trivy,
      csv,
      "--format",
      "json",
      "--output",
      output,
      "--fail-on-scan-set-change",
    ]);

    expect(failure).toMatchObject({ code: 1, stdout: "" });
    expect(failure.stderr).toContain("Scan set changed");
    const diff = JSON.parse(await readFile(output, "utf8")) as {
      scanSetChange: { detected: boolean; addedTools: string[] };
    };
    expect(diff.scanSetChange).toMatchObject({ detected: true, addedTools: ["Legacy Scanner"] });
  });

  it("warns but succeeds by default when the scanner set changes", async () => {
    const output = join(testDirectory, "scan-set-warning.json");
    const result = await execute(process.execPath, [
      cli,
      "diff",
      "--baseline",
      trivy,
      trivy,
      csv,
      "--format",
      "json",
      "--output",
      output,
    ]);

    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Scan set changed");
    expect(JSON.parse(await readFile(output, "utf8"))).toMatchObject({
      scanSetChange: { detected: true },
    });
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
    expect(html).toContain('id="coverage-filter"');
    expect(html).toContain("Scanner divergence");
    expect(html).toContain("This self-contained file makes no network requests.");
  });

  it("accepts JSON files with a UTF-8 BOM", async () => {
    const input = join(testDirectory, "bom.json");
    const output = join(testDirectory, "bom-result.json");
    await writeFile(input, `\uFEFF${await readFile(trivy, "utf8")}`, "utf8");
    await execute(process.execPath, [cli, "merge", input, "--format", "json", "--output", output]);
    const result = JSON.parse(await readFile(output, "utf8")) as {
      reports: Array<{ format: string; tool: string }>;
    };
    expect(result.reports[0]).toMatchObject({ format: "trivy", tool: "Trivy" });
  });

  it("expands a quoted report glob without relying on the shell", async () => {
    const first = join(testDirectory, "a-trivy.json");
    await writeFile(first, await readFile(trivy, "utf8"), "utf8");
    await writeFile(join(testDirectory, "b-grype.json"), await readFile(grype, "utf8"), "utf8");
    await mkdir(join(testDirectory, "ignored-directory.json"));

    const inspection = await execute(process.execPath, [
      cli,
      "inspect",
      first,
      join(testDirectory, "*.json"),
      "--json",
    ]);
    const reports = JSON.parse(inspection.stdout) as Array<{ format: string; tool: string }>;

    expect(reports).toEqual([
      expect.objectContaining({ format: "trivy", tool: "Trivy" }),
      expect.objectContaining({ format: "grype", tool: "Grype" }),
    ]);
  });

  it("treats an existing filename with glob characters as a literal path", async () => {
    const bracketed = join(testDirectory, "[trivy].json");
    await writeFile(bracketed, await readFile(trivy, "utf8"), "utf8");

    const detection = await execute(process.execPath, [cli, "detect", bracketed]);

    expect(detection.stdout).toBe("trivy\n");
  });

  it("fails clearly when a report pattern matches no files", async () => {
    const pattern = join(testDirectory, "missing-*.json");
    const failure = await executeFailure([cli, "inspect", pattern]);

    expect(failure).toMatchObject({ code: 1, stdout: "" });
    expect(failure.stderr).toContain(`Report pattern '${pattern}' did not match any files.`);
    expect(failure.stderr).not.toMatch(/\n\s+at /);
  });

  it("requires a detect pattern to match exactly one file", async () => {
    await writeFile(join(testDirectory, "a.json"), await readFile(trivy, "utf8"), "utf8");
    await writeFile(join(testDirectory, "b.json"), await readFile(grype, "utf8"), "utf8");

    const failure = await executeFailure([cli, "detect", join(testDirectory, "*.json")]);

    expect(failure).toMatchObject({ code: 1, stdout: "" });
    expect(failure.stderr).toContain("detect requires exactly one report; the pattern matched 2.");
  });

  it("applies the report-count limit after glob expansion", async () => {
    await Promise.all(
      Array.from({ length: 1_001 }, (_, index) =>
        writeFile(join(testDirectory, `report-${String(index).padStart(4, "0")}.json`), "{}"),
      ),
    );

    const failure = await executeFailure([cli, "inspect", join(testDirectory, "*.json")]);

    expect(failure).toMatchObject({ code: 1, stdout: "" });
    expect(failure.stderr).toContain("At most 1000 reports can be processed in one invocation.");
  });

  it("expands baseline and current report patterns independently", async () => {
    const baselineDirectory = join(testDirectory, "baseline");
    const currentDirectory = join(testDirectory, "current");
    await mkdir(baselineDirectory);
    await mkdir(currentDirectory);
    await writeFile(join(baselineDirectory, "trivy.json"), await readFile(trivy, "utf8"), "utf8");
    await writeFile(join(currentDirectory, "trivy.json"), await readFile(trivy, "utf8"), "utf8");
    await writeFile(join(currentDirectory, "grype.json"), await readFile(grype, "utf8"), "utf8");
    const output = join(testDirectory, "diff.json");

    await execute(process.execPath, [
      cli,
      "diff",
      "--baseline",
      join(baselineDirectory, "*.json"),
      join(currentDirectory, "*.json"),
      "--format",
      "json",
      "--output",
      output,
    ]);
    const result = JSON.parse(await readFile(output, "utf8")) as {
      summary: {
        baselineClusters: number;
        currentClusters: number;
        new: number;
        unchanged: number;
      };
    };

    expect(result.summary).toMatchObject({
      baselineClusters: 2,
      currentClusters: 3,
      new: 1,
      unchanged: 1,
    });
  });
});

async function executeFailure(args: string[]): Promise<{
  code: number | string;
  stdout: string;
  stderr: string;
}> {
  try {
    await execute(process.execPath, args);
    throw new Error("Expected the CLI invocation to fail.");
  } catch (error) {
    return error as { code: number | string; stdout: string; stderr: string };
  }
}

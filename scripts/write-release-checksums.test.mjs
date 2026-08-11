import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";

import { writeReleaseChecksums } from "./write-release-checksums.mjs";

const testRoot = join(process.cwd(), "work");

async function withFixtureDirectory(run) {
  await mkdir(testRoot, { recursive: true });
  const directory = await mkdtemp(join(testRoot, "release-checksums-"));
  try {
    await run(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test("writes a deterministic basename-only checksum manifest", async () => {
  await withFixtureDirectory(async (directory) => {
    const outputPath = join(directory, "SHA256SUMS.txt");
    await writeFile(join(directory, "zeta.tgz"), "alpha");
    await writeFile(join(directory, "alpha.cdx.json"), "beta");
    await writeFile(outputPath, "stale manifest that must not hash itself\n");

    const entries = await writeReleaseChecksums(directory, outputPath);
    const manifest = await readFile(outputPath, "utf8");

    assert.deepEqual(
      entries.map((entry) => entry.name),
      ["alpha.cdx.json", "zeta.tgz"],
    );
    assert.equal(
      manifest,
      [
        "f44e64e75f3948e9f73f8dfa94721c4ce8cbb4f265c4790c702b2d41cfbf2753  alpha.cdx.json",
        "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8  zeta.tgz",
        "",
      ].join("\n"),
    );
    assert.doesNotMatch(manifest, /release[\\/]/);
    assert.doesNotMatch(manifest, /SHA256SUMS\.txt/);
  });
});

test("refuses to emit a manifest for an empty release directory", async () => {
  await withFixtureDirectory(async (directory) => {
    await assert.rejects(
      writeReleaseChecksums(directory, join(directory, "SHA256SUMS.txt")),
      /no release artifacts/i,
    );
  });
});

test("rejects a nonportable release name without replacing the manifest", async () => {
  await withFixtureDirectory(async (directory) => {
    const outputPath = join(directory, "SHA256SUMS.txt");
    await writeFile(join(directory, "unsafe asset.tgz"), "payload");
    await writeFile(outputPath, "keep this manifest\n");

    await assert.rejects(writeReleaseChecksums(directory, outputPath), /not portable/i);
    assert.equal(await readFile(outputPath, "utf8"), "keep this manifest\n");
  });
});

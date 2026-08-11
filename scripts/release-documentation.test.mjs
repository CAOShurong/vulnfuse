import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { URL } from "node:url";

test("README uses the verifiable provenance command for the current release", async () => {
  const [packageText, readme] = await Promise.all([
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../README.md", import.meta.url), "utf8"),
  ]);
  const { version } = JSON.parse(packageText);

  assert.match(readme, new RegExp(`gh attestation verify vulnfuse-${version}\\.tgz`));
  assert.match(readme, /--signer-workflow CAOShurong\/vulnfuse\/\.github\/workflows\/release\.yml/);
  assert.match(readme, new RegExp(`--source-ref refs/tags/v${version}`));
  assert.match(readme, /--deny-self-hosted-runners/);
  assert.doesNotMatch(readme, /^gh release verify(?:-asset)?\b/m);
});

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readdir, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const portableAssetName = /^[A-Za-z0-9][A-Za-z0-9._+@-]*$/;

async function sha256File(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk);
  }
  return hash.digest("hex");
}

export async function writeReleaseChecksums(directoryPath, outputPath) {
  const directory = resolve(directoryPath);
  const output = resolve(outputPath);
  const outputName = basename(output);
  const directoryEntries = await readdir(directory, { withFileTypes: true });
  const artifactNames = directoryEntries
    .filter((entry) => entry.isFile() && resolve(directory, entry.name) !== output)
    .map((entry) => entry.name)
    .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));

  if (artifactNames.length === 0) {
    throw new Error(`No release artifacts found in ${directory}`);
  }

  for (const name of artifactNames) {
    if (!portableAssetName.test(name)) {
      throw new Error(
        `Release asset name ${JSON.stringify(name)} is not portable in ${outputName}`,
      );
    }
  }

  const entries = [];
  for (const name of artifactNames) {
    entries.push({
      digest: await sha256File(resolve(directory, name)),
      name,
    });
  }

  const manifest = `${entries.map((entry) => `${entry.digest}  ${entry.name}`).join("\n")}\n`;
  await writeFile(output, manifest, "utf8");
  return entries;
}

const isCommand =
  process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url;

if (isCommand) {
  const [directoryPath, outputPath, ...extra] = process.argv.slice(2);
  if (!directoryPath || !outputPath || extra.length > 0) {
    process.stderr.write(
      "Usage: node scripts/write-release-checksums.mjs <artifact-directory> <manifest-path>\n",
    );
    process.exitCode = 1;
  } else {
    try {
      const entries = await writeReleaseChecksums(directoryPath, outputPath);
      process.stdout.write(`Wrote ${entries.length} checksums to ${outputPath}\n`);
    } catch (error) {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    }
  }
}

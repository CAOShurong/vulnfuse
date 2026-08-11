import { lstat, rm } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const target = resolve(process.cwd(), "dist");
const parts = relative(repository, target).split(sep);

if (
  parts.length !== 3 ||
  !["apps", "packages"].includes(parts[0] ?? "") ||
  !parts[1] ||
  parts[2] !== "dist"
) {
  throw new Error(`Refusing to clean a non-workspace dist path: ${target}`);
}

const metadata = await lstat(target).catch((error) => {
  if (error?.code === "ENOENT") return undefined;
  throw error;
});
if (metadata?.isSymbolicLink()) {
  throw new Error(`Refusing to clean a symbolic-link dist path: ${target}`);
}

await rm(target, { recursive: true, force: true });

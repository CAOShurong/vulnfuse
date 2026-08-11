import { randomUUID } from "node:crypto";
import { mkdir, open, rename, unlink, writeFile } from "node:fs/promises";
import { basename, dirname, isAbsolute, relative, resolve, sep } from "node:path";

const readChunkSize = 64 * 1024;

/**
 * Labels local report files without persisting checkout-, runner-, or user-specific roots.
 * Actual filesystem paths remain available to the caller for reads and local diagnostics.
 */
export function portableReportNames(paths: string[], root = process.cwd()): string[] {
  const absoluteRoot = resolve(root);
  const candidates = paths.map((path) => {
    if (path === "-") return "stdin";
    const absolute = resolve(path);
    const fromRoot = relative(absoluteRoot, absolute);
    if (
      fromRoot.length > 0 &&
      !isAbsolute(fromRoot) &&
      fromRoot !== ".." &&
      !fromRoot.startsWith(`..${sep}`)
    ) {
      return fromRoot.split(sep).join("/");
    }
    return `external-report/${basename(absolute)}`;
  });
  const totals = new Map<string, number>();
  for (const candidate of candidates) {
    totals.set(candidate, (totals.get(candidate) ?? 0) + 1);
  }
  const occurrences = new Map<string, number>();
  return candidates.map((candidate) => {
    if ((totals.get(candidate) ?? 0) === 1) return candidate;
    const occurrence = (occurrences.get(candidate) ?? 0) + 1;
    occurrences.set(candidate, occurrence);
    if (candidate.startsWith("external-report/")) {
      return `external-report/${occurrence}-${candidate.slice("external-report/".length)}`;
    }
    return `${candidate}#${occurrence}`;
  });
}

export async function readFileLimited(path: string, maxBytes: number): Promise<string> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new RangeError("maxBytes must be a non-negative safe integer.");
  }
  const handle = await open(path, "r");
  try {
    const { size } = await handle.stat();
    if (size > maxBytes) {
      throw new Error(
        `${path} is ${size.toLocaleString()} bytes; the configured limit is ${maxBytes.toLocaleString()} bytes.`,
      );
    }

    const chunks: Buffer[] = [];
    let length = 0;
    while (true) {
      const buffer = Buffer.allocUnsafe(Math.min(readChunkSize, maxBytes - length + 1));
      const { bytesRead } = await handle.read(buffer, 0, buffer.byteLength, null);
      if (bytesRead === 0) break;
      length += bytesRead;
      if (length > maxBytes) {
        throw new Error(
          `${path} exceeded the configured ${maxBytes.toLocaleString()} byte limit while reading.`,
        );
      }
      chunks.push(buffer.subarray(0, bytesRead));
    }
    return Buffer.concat(chunks, length).toString("utf8");
  } finally {
    await handle.close();
  }
}

export async function writeFileAtomic(path: string, content: string): Promise<void> {
  const destination = resolve(path);
  await mkdir(dirname(destination), { recursive: true });
  const temporary = `${destination}.vulnfuse-${process.pid}-${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, content, { encoding: "utf8", flag: "wx", flush: true });
    await rename(temporary, destination);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

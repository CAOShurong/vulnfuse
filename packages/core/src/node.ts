import { randomUUID } from "node:crypto";
import { mkdir, open, rename, unlink, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const readChunkSize = 64 * 1024;

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

import { open } from "node:fs/promises";

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

import { beforeEach, describe, expect, it, vi } from "vitest";

const fileSystem = vi.hoisted(() => ({
  mkdir: vi.fn(),
  open: vi.fn(),
  rename: vi.fn(),
  unlink: vi.fn(),
  writeFile: vi.fn(),
}));

vi.mock("node:fs/promises", () => fileSystem);

import { readFileLimited, writeFileAtomic } from "../src/node.js";

beforeEach(() => {
  vi.clearAllMocks();
  fileSystem.mkdir.mockResolvedValue(undefined);
  fileSystem.rename.mockResolvedValue(undefined);
  fileSystem.unlink.mockResolvedValue(undefined);
  fileSystem.writeFile.mockResolvedValue(undefined);
});

describe("readFileLimited", () => {
  it("rejects an invalid limit before opening a file", async () => {
    await expect(readFileLimited("report.json", -1)).rejects.toThrow(
      "maxBytes must be a non-negative safe integer.",
    );
    expect(fileSystem.open).not.toHaveBeenCalled();
  });

  it("rejects a known oversized file before reading content", async () => {
    const handle = fakeHandle({ size: 11 });
    fileSystem.open.mockResolvedValue(handle);

    await expect(readFileLimited("large.json", 10)).rejects.toThrow(
      "large.json is 11 bytes; the configured limit is 10 bytes.",
    );
    expect(handle.read).not.toHaveBeenCalled();
    expect(handle.close).toHaveBeenCalledOnce();
  });

  it("stops after maxBytes plus one when a file grows after stat", async () => {
    const handle = fakeHandle({ size: 0 }, [Buffer.from("1234"), Buffer.from("56")]);
    fileSystem.open.mockResolvedValue(handle);

    await expect(readFileLimited("growing.json", 5)).rejects.toThrow(
      "growing.json exceeded the configured 5 byte limit while reading.",
    );
    expect(handle.read).toHaveBeenCalledTimes(2);
    expect(handle.close).toHaveBeenCalledOnce();
  });

  it("accepts a file exactly at the byte limit", async () => {
    const handle = fakeHandle({ size: 5 }, [Buffer.from("12345")]);
    fileSystem.open.mockResolvedValue(handle);

    await expect(readFileLimited("exact.json", 5)).resolves.toBe("12345");
    expect(handle.close).toHaveBeenCalledOnce();
  });

  it("closes the handle when an incremental read fails", async () => {
    const handle = fakeHandle({ size: 0 });
    handle.read.mockRejectedValue(new Error("read failed"));
    fileSystem.open.mockResolvedValue(handle);

    await expect(readFileLimited("broken.json", 5)).rejects.toThrow("read failed");
    expect(handle.close).toHaveBeenCalledOnce();
  });
});

describe("writeFileAtomic", () => {
  it("flushes a unique temporary sibling before replacing the destination", async () => {
    await writeFileAtomic("reports/result.json", "complete report");

    expect(fileSystem.mkdir).toHaveBeenCalledWith(expect.stringMatching(/[\\/]reports$/), {
      recursive: true,
    });
    expect(fileSystem.writeFile).toHaveBeenCalledWith(
      expect.stringMatching(/result\.json\.vulnfuse-\d+-[0-9a-f-]+\.tmp$/),
      "complete report",
      { encoding: "utf8", flag: "wx", flush: true },
    );
    const temporary = fileSystem.writeFile.mock.calls[0]?.[0];
    expect(fileSystem.rename).toHaveBeenCalledWith(
      temporary,
      expect.stringMatching(/[\\/]reports[\\/]result\.json$/),
    );
    expect(fileSystem.unlink).not.toHaveBeenCalled();
  });

  it("removes the temporary sibling when a write fails", async () => {
    fileSystem.writeFile.mockRejectedValueOnce(new Error("partial write"));

    await expect(writeFileAtomic("report.json", "complete report")).rejects.toThrow(
      "partial write",
    );

    const temporary = fileSystem.writeFile.mock.calls[0]?.[0];
    expect(fileSystem.rename).not.toHaveBeenCalled();
    expect(fileSystem.unlink).toHaveBeenCalledWith(temporary);
  });
});

function fakeHandle(stat: { size: number }, chunks: Buffer[] = []) {
  let index = 0;
  return {
    stat: vi.fn().mockResolvedValue(stat),
    read: vi.fn().mockImplementation(async (buffer: Buffer) => {
      const chunk = chunks[index++];
      if (!chunk) return { bytesRead: 0, buffer };
      chunk.copy(buffer, 0, 0, Math.min(chunk.length, buffer.length));
      return { bytesRead: Math.min(chunk.length, buffer.length), buffer };
    }),
    close: vi.fn().mockResolvedValue(undefined),
  };
}

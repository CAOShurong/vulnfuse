import { copyFile } from "node:fs/promises";
import { resolve } from "node:path";

await copyFile(resolve(process.cwd(), "../../LICENSE"), resolve(process.cwd(), "LICENSE"));
await copyFile(
  resolve(process.cwd(), "../../THIRD_PARTY_NOTICES.md"),
  resolve(process.cwd(), "THIRD_PARTY_NOTICES.md"),
);

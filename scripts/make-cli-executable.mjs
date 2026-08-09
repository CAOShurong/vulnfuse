import { chmod, readFile, writeFile } from "node:fs/promises";
import { URL } from "node:url";

const path = new URL("../packages/cli/dist/index.js", import.meta.url);
const source = await readFile(path, "utf8");
const shebang = "#!/usr/bin/env node\n";

if (!source.startsWith(shebang)) {
  await writeFile(path, `${shebang}${source}`, "utf8");
}

await chmod(path, 0o755);

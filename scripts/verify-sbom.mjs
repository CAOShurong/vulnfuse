import { readFile } from "node:fs/promises";

const [path, ...expectedNames] = process.argv.slice(2);
if (!path || expectedNames.length === 0) {
  throw new Error("Usage: node scripts/verify-sbom.mjs <sbom.json> <expected-package>...");
}

const document = JSON.parse(await readFile(path, "utf8"));
if (document.bomFormat !== "CycloneDX" || !Array.isArray(document.components)) {
  throw new Error(`${path} is not a CycloneDX document with a component list.`);
}

const missing = expectedNames.filter(
  (name) =>
    !document.components.some(
      (component) =>
        component?.name === name ||
        (typeof component?.["bom-ref"] === "string" && component["bom-ref"].startsWith(`${name}@`)),
    ),
);
if (missing.length > 0) {
  throw new Error(`${path} is missing expected components: ${missing.join(", ")}.`);
}

process.stdout.write(
  `${path} contains ${document.components.length} components, including ${expectedNames.join(", ")}.\n`,
);

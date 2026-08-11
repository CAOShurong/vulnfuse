import { access, readFile, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const required = [
  "LICENSE",
  "THIRD_PARTY_NOTICES.md",
  "README.md",
  "SECURITY.md",
  "CONTRIBUTING.md",
  "action.yml",
  "package-lock.json",
  "scripts/clean-workspace-dist.mjs",
  "scripts/verify-sbom.mjs",
  "packages/action/dist/index.cjs",
  "packages/core/test/fixtures/README.md",
  "docs/MATCHING.md",
  "docs/FORMATS.md",
  "docs/THREAT_MODEL.md",
  "docs/RESEARCH.md",
];

for (const path of required) await access(resolve(root, path));

const thirdPartyNotices = await readFile(resolve(root, "THIRD_PARTY_NOTICES.md"), "utf8");
if (
  !thirdPartyNotices.includes("@rgrove/parse-xml 4.2.3") ||
  !thirdPartyNotices.includes("ISC License")
) {
  throw new Error("THIRD_PARTY_NOTICES.md must retain the bundled XML parser license notice.");
}

const packageFiles = [
  "package.json",
  "packages/core/package.json",
  "packages/cli/package.json",
  "packages/action/package.json",
  "apps/web/package.json",
];
const packages = await Promise.all(
  packageFiles.map(async (path) => JSON.parse(await readFile(resolve(root, path), "utf8"))),
);
const versions = new Set(packages.map((manifest) => manifest.version).filter(Boolean));
const expectedVersion = packages[0].version;
if (typeof expectedVersion !== "string" || versions.size !== 1) {
  throw new Error(`Workspace package versions must all match; found ${[...versions].join(", ")}.`);
}

const embeddedVersions = [
  ["packages/cli/src/index.ts", `const version = "${expectedVersion}"`],
  ["packages/core/src/exporters/html.ts", `VulnFuse ${expectedVersion}`],
  ["packages/core/src/exporters/sarif.ts", `semanticVersion: "${expectedVersion}"`],
  ["packages/core/src/exporters/baseline.ts", `semanticVersion: "${expectedVersion}"`],
];
for (const [path, expectedText] of embeddedVersions) {
  const content = await readFile(resolve(root, path), "utf8");
  if (!content.includes(expectedText)) {
    throw new Error(`${path} does not embed workspace version ${expectedVersion}.`);
  }
}

const actionMetadata = await readFile(resolve(root, "action.yml"), "utf8");
if (!/using:\s*node24\b/.test(actionMetadata))
  throw new Error("action.yml must use the Node 24 runtime.");
if (!/main:\s*packages\/action\/dist\/index\.cjs\b/.test(actionMetadata)) {
  throw new Error("action.yml does not point to the committed bundle.");
}
const actionBundle = await stat(resolve(root, "packages/action/dist/index.cjs"));
if (actionBundle.size < 100_000)
  throw new Error("The committed GitHub Action bundle looks incomplete.");

const workflowText = await Promise.all(
  ["ci.yml", "pages.yml", "codeql.yml", "release.yml"].map((name) =>
    readFile(resolve(root, ".github/workflows", name), "utf8"),
  ),
);
const obsoleteActionPatterns = [
  /actions\/checkout@v[1-6]\b/,
  /actions\/setup-node@v[1-6]\b/,
  /actions\/upload-artifact@v[1-6]\b/,
  /actions\/configure-pages@v[1-5]\b/,
  /actions\/upload-pages-artifact@v[1-4]\b/,
  /actions\/deploy-pages@v[1-4]\b/,
];
for (const pattern of obsoleteActionPatterns) {
  if (workflowText.some((content) => pattern.test(content))) {
    throw new Error(`An obsolete GitHub Action reference matched ${pattern}.`);
  }
}

const markdownFiles = [
  "README.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "docs/ARCHITECTURE.md",
  "docs/FORMATS.md",
  "docs/MATCHING.md",
  "docs/THREAT_MODEL.md",
];
for (const markdownPath of markdownFiles) {
  const content = await readFile(resolve(root, markdownPath), "utf8");
  for (const match of content.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)) {
    const target = match[1]?.split("#", 1)[0];
    if (!target || /^(?:https?:|mailto:|#)/.test(target)) continue;
    await access(resolve(dirname(resolve(root, markdownPath)), decodeURIComponent(target))).catch(
      () => {
        throw new Error(`${markdownPath} links to missing local target ${target}.`);
      },
    );
  }
}

process.stdout.write("Repository checks passed.\n");

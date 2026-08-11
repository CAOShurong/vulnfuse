import { parseXml, type XmlElement } from "@rgrove/parse-xml";

import type { ParsedReport } from "../model.js";
import { asRecord } from "../utils.js";
import { parseCycloneDx } from "./cyclonedx.js";

const CYCLONEDX_NAMESPACE = /^https?:\/\/cyclonedx\.org\/schema\/bom\/(1\.[0-9]+)$/i;
const DOCUMENT_TYPE = /<!DOCTYPE\b/i;

const collectionElements = new Map<string, ReadonlySet<string>>([
  ["components", new Set(["component"])],
  ["services", new Set(["service"])],
  ["vulnerabilities", new Set(["vulnerability"])],
  ["ratings", new Set(["rating"])],
  ["cwes", new Set(["cwe"])],
  ["references", new Set(["reference"])],
  ["advisories", new Set(["advisory"])],
  ["affects", new Set(["target"])],
  ["versions", new Set(["version"])],
  ["responses", new Set(["response"])],
  ["properties", new Set(["property"])],
]);

export function looksLikeCycloneDxXml(content: string): boolean {
  const head = content.slice(0, 4096);
  const root = head.match(/<(?![!?])(?:(?<prefix>[A-Za-z_][\w.-]*):)?bom\b(?<attributes>[^>]*)>/i);
  if (!root?.groups) return false;
  const prefix = root.groups["prefix"];
  const namespaceName = prefix ? `xmlns:${prefix}` : "xmlns";
  const namespace = attributeValue(root.groups["attributes"] ?? "", namespaceName);
  return Boolean(namespace && CYCLONEDX_NAMESPACE.test(namespace));
}

export function parseCycloneDxXml(content: string, reportName: string): ParsedReport {
  if (DOCUMENT_TYPE.test(content)) {
    throw new Error(
      `${reportName} contains a DOCTYPE declaration; CycloneDX XML DTDs and custom entities are not supported.`,
    );
  }

  let root: XmlElement | null;
  try {
    root = parseXml(content).root;
  } catch (error) {
    throw new Error(
      `${reportName} is not valid CycloneDX XML: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
  if (!root) throw new Error(`${reportName} is not valid CycloneDX XML: the document is empty.`);

  const rootName = qualifiedName(root.name);
  if (rootName.local !== "bom") {
    throw new Error(`${reportName} is not CycloneDX XML: expected a bom root element.`);
  }
  const namespaceName = rootName.prefix ? `xmlns:${rootName.prefix}` : "xmlns";
  const namespace = root.attributes[namespaceName];
  const namespaceMatch = namespace?.match(CYCLONEDX_NAMESPACE);
  if (!namespace || !namespaceMatch) {
    throw new Error(`${reportName} is not CycloneDX XML: the bom namespace is unsupported.`);
  }

  const value = elementValue(root, rootName.prefix, namespace, 0);
  const record = asRecord(value);
  if (!record) throw new Error(`${reportName} is not valid CycloneDX XML.`);
  record["bomFormat"] = "CycloneDX";
  record["specVersion"] = namespaceMatch[1] ?? "unknown";
  return parseCycloneDx(record, reportName);
}

function elementValue(
  element: XmlElement,
  expectedPrefix: string | undefined,
  expectedNamespace: string,
  depth: number,
): unknown {
  if (depth > 100) throw new Error("CycloneDX XML element nesting exceeds the limit of 100.");
  const ownName = qualifiedName(element.name);
  if (ownName.prefix !== expectedPrefix) return undefined;
  const namespaceName = expectedPrefix ? `xmlns:${expectedPrefix}` : "xmlns";
  const declaredNamespace = element.attributes[namespaceName];
  if (declaredNamespace && declaredNamespace !== expectedNamespace) return undefined;

  const elementChildren = element.children.filter(
    (child): child is XmlElement => child.type === "element",
  );
  if (elementChildren.length === 0) return element.text.trim();

  const collection = collectionElements.get(ownName.local);
  if (
    collection &&
    elementChildren.every((child) => {
      const childName = qualifiedName(child.name);
      return childName.prefix === expectedPrefix && collection.has(childName.local);
    })
  ) {
    return elementChildren
      .map((child) => elementValue(child, expectedPrefix, expectedNamespace, depth + 1))
      .filter((value) => value !== undefined);
  }

  if (ownName.local === "tools") {
    const toolChildren = elementChildren.filter((child) => {
      const childName = qualifiedName(child.name);
      return childName.prefix === expectedPrefix && childName.local === "tool";
    });
    if (toolChildren.length === elementChildren.length) {
      return toolChildren
        .map((child) => elementValue(child, expectedPrefix, expectedNamespace, depth + 1))
        .filter((value) => value !== undefined);
    }
  }

  const result: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(element.attributes)) {
    if (name === "xmlns" || name.startsWith("xmlns:")) continue;
    const attrName = qualifiedName(name);
    if (!attrName.prefix) result[attrName.local] = value;
  }

  for (const child of elementChildren) {
    const childName = qualifiedName(child.name);
    if (childName.prefix !== expectedPrefix) continue;
    const value = elementValue(child, expectedPrefix, expectedNamespace, depth + 1);
    if (value === undefined) continue;
    const previous = result[childName.local];
    if (previous === undefined) result[childName.local] = value;
    else if (Array.isArray(previous)) previous.push(value);
    else result[childName.local] = [previous, value];
  }
  return result;
}

function qualifiedName(name: string): { prefix?: string; local: string } {
  const separator = name.indexOf(":");
  if (separator < 0) return { local: name };
  return { prefix: name.slice(0, separator), local: name.slice(separator + 1) };
}

function attributeValue(attributes: string, name: string): string | undefined {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = attributes.match(new RegExp(`(?:^|\\s)${escaped}\\s*=\\s*(["'])(.*?)\\1`, "i"));
  return match?.[2];
}

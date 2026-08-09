import type { FindingIdentifier } from "./model.js";
import { normalizeWhitespace, uniqueBy } from "./utils.js";

const identifierPatterns: Array<{ scheme: string; pattern: RegExp }> = [
  { scheme: "CVE", pattern: /\bCVE-\d{4}-\d{4,}\b/gi },
  {
    scheme: "GHSA",
    pattern: /\bGHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}\b/gi,
  },
  { scheme: "CWE", pattern: /\bCWE-\d{1,5}\b/gi },
  {
    scheme: "OSV",
    pattern: /\b(?:OSV|PYSEC|RUSTSEC|GO|GSD|MAL|UBUNTU|DEBIAN)-\d{4}-[A-Z0-9._-]+\b/gi,
  },
];

export function normalizeIdentifier(
  value: string,
  relationship: FindingIdentifier["relationship"] = "primary",
  schemeHint?: string,
): FindingIdentifier | undefined {
  const normalized = normalizeWhitespace(value)
    .replace(/[),.;:]+$/, "")
    .toUpperCase();
  if (!normalized) return undefined;

  let scheme = schemeHint?.trim().toUpperCase();
  if (!scheme) {
    if (/^CVE-\d{4}-\d{4,}$/.test(normalized)) scheme = "CVE";
    else if (/^GHSA-[23456789CFGHJMPQRVWX]{4}(?:-[23456789CFGHJMPQRVWX]{4}){2}$/.test(normalized))
      scheme = "GHSA";
    else if (/^CWE-\d{1,5}$/.test(normalized)) scheme = "CWE";
    else scheme = normalized.split("-", 1)[0] || "ID";
  }

  const inferredRelationship = scheme === "CWE" ? "weakness" : relationship;
  return { scheme, value: normalized, relationship: inferredRelationship };
}

export function extractIdentifiers(
  values: Array<string | undefined>,
  relationship: FindingIdentifier["relationship"] = "related",
): FindingIdentifier[] {
  const identifiers: FindingIdentifier[] = [];
  for (const value of values) {
    if (!value) continue;
    for (const { scheme, pattern } of identifierPatterns) {
      for (const match of value.matchAll(pattern)) {
        const identifier = normalizeIdentifier(match[0], relationship, scheme);
        if (identifier) identifiers.push(identifier);
      }
    }
  }
  return uniqueIdentifiers(identifiers);
}

export function uniqueIdentifiers(values: FindingIdentifier[]): FindingIdentifier[] {
  const priority: Record<FindingIdentifier["relationship"], number> = {
    primary: 5,
    alias: 4,
    related: 3,
    weakness: 2,
    rule: 1,
  };
  const sorted = [...values].sort((a, b) => priority[b.relationship] - priority[a.relationship]);
  return uniqueBy(sorted, identifierKey);
}

export function identifierKey(identifier: FindingIdentifier): string {
  return `${identifier.scheme}:${identifier.value}`.toUpperCase();
}

export function isVulnerabilityIdentifier(identifier: FindingIdentifier): boolean {
  return !["weakness", "rule"].includes(identifier.relationship) && identifier.scheme !== "CWE";
}

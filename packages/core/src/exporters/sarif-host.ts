import type { FindingCluster } from "../model.js";

const maximumHostedRuleTags = 9;
const maximumHostedRuleNameLength = 255;
const maximumHostedDescriptionLength = 1024;
export const maximumHostedResultMessageLength = 1024;

const identifierRelationshipPriority: Record<
  FindingCluster["identifiers"][number]["relationship"],
  number
> = { primary: 5, alias: 4, related: 3, weakness: 2, rule: 1 };

export function hostedSarifRule(
  cluster: FindingCluster,
  securitySeverity: string,
): Record<string, unknown> {
  const originalName = cluster.identifiers[0]?.value ?? cluster.id;
  const name = boundHostedSarifText(originalName, maximumHostedRuleNameLength);
  const shortDescription = boundHostedSarifText(
    cluster.primary.title,
    maximumHostedDescriptionLength,
  );
  const fullDescription = cluster.primary.description
    ? boundHostedSarifText(cluster.primary.description, maximumHostedDescriptionLength)
    : undefined;
  const truncatedFields = [
    ...(name.truncated ? ["name"] : []),
    ...(shortDescription.truncated ? ["shortDescription.text"] : []),
    ...(fullDescription?.truncated ? ["fullDescription.text"] : []),
  ];
  const identifierTags = [...cluster.identifiers]
    .sort((left, right) => {
      const relationshipDelta =
        identifierRelationshipPriority[right.relationship] -
        identifierRelationshipPriority[left.relationship];
      if (relationshipDelta !== 0) return relationshipDelta;
      return `${left.scheme}:${left.value}`.localeCompare(`${right.scheme}:${right.value}`);
    })
    .map((identifier) => identifier.value);
  const identifierTagBudget = maximumHostedRuleTags - 2;
  const omittedIdentifierTagCount = Math.max(0, identifierTags.length - identifierTagBudget);

  return {
    id: cluster.id,
    name: name.text,
    shortDescription: { text: shortDescription.text },
    ...(fullDescription ? { fullDescription: { text: fullDescription.text } } : {}),
    ...(cluster.primary.references[0] ? { helpUri: cluster.primary.references[0] } : {}),
    properties: {
      tags: ["security", cluster.primary.kind, ...identifierTags.slice(0, identifierTagBudget)],
      ...(omittedIdentifierTagCount > 0
        ? { vulnfuseOmittedIdentifierTagCount: omittedIdentifierTagCount }
        : {}),
      ...(name.truncated ? { vulnfuseOriginalName: originalName } : {}),
      ...(shortDescription.truncated
        ? { vulnfuseOriginalShortDescription: cluster.primary.title }
        : {}),
      ...(fullDescription?.truncated
        ? { vulnfuseOriginalFullDescription: cluster.primary.description }
        : {}),
      ...(truncatedFields.length > 0 ? { vulnfuseTruncatedFields: truncatedFields } : {}),
      "security-severity": securitySeverity,
    },
  };
}

export function boundHostedSarifText(
  value: string,
  maximumUtf16Length: number,
): { text: string; truncated: boolean } {
  if (value.length <= maximumUtf16Length) return { text: value, truncated: false };

  const contentBudget = maximumUtf16Length - 1;
  let text = "";
  for (const character of value) {
    if (text.length + character.length > contentBudget) break;
    text += character;
  }
  return { text: `${text}…`, truncated: true };
}

export function validateSarifFallbackLocation(value: string): string {
  if (!value || value.trim() !== value) {
    throw new Error("SARIF fallback location must be a non-empty repository-relative URI.");
  }
  if (/[\\?#\s]/u.test(value) || containsControlCharacter(value)) {
    throw new Error(
      "SARIF fallback location must use forward slashes and contain no whitespace, query, fragment, or control characters.",
    );
  }
  if (value.startsWith("/") || /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(value)) {
    throw new Error("SARIF fallback location must be relative to the repository root.");
  }

  const segments = value.split("/");
  for (const [index, segment] of segments.entries()) {
    if (!segment) {
      throw new Error("SARIF fallback location must not contain empty path segments.");
    }
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw new Error("SARIF fallback location contains invalid percent encoding.");
    }
    if (
      decoded === "." ||
      decoded === ".." ||
      decoded.includes("/") ||
      decoded.includes("\\") ||
      /[%?#\s]/u.test(decoded) ||
      containsControlCharacter(decoded) ||
      (index === 0 && /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(decoded))
    ) {
      throw new Error(
        "SARIF fallback location must not contain traversal, nested encoding, encoded separators, whitespace, query, fragment, control characters, or an absolute URI scheme.",
      );
    }
  }
  return value;
}

function containsControlCharacter(value: string): boolean {
  return [...value].some((character) => {
    const codePoint = character.codePointAt(0) ?? 0;
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
}

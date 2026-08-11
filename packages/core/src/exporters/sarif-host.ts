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

import type {
  CanonicalFinding,
  CorrelationOptions,
  MatchBlocker,
  MatchExplanation,
  MatchReason,
} from "./model.js";
import { defaultCorrelationOptions } from "./model.js";
import { identifierKey, isVulnerabilityIdentifier } from "./identifiers.js";
import { assetKey, componentKey, normalizePath } from "./utils.js";

const stopWords = new Set([
  "a",
  "an",
  "and",
  "at",
  "by",
  "for",
  "from",
  "in",
  "is",
  "of",
  "on",
  "or",
  "the",
  "to",
  "via",
  "with",
  "vulnerability",
]);

function titleTokens(value: string): Set<string> {
  return new Set(
    value
      .toLowerCase()
      .replace(/[^a-z0-9._-]+/g, " ")
      .split(/\s+/)
      .filter((token) => token.length > 1 && !stopWords.has(token)),
  );
}

function jaccard(left: Set<string>, right: Set<string>): number {
  if (left.size === 0 || right.size === 0) return 0;
  let intersection = 0;
  for (const item of left) if (right.has(item)) intersection += 1;
  return intersection / (left.size + right.size - intersection);
}

function fingerprintMatches(left: CanonicalFinding, right: CanonicalFinding): string[] {
  const rightValues = new Set(Object.values(right.fingerprints));
  return Object.values(left.fingerprints).filter(
    (value) => value.length > 0 && rightValues.has(value),
  );
}

function vulnerabilityIds(finding: CanonicalFinding): Set<string> {
  return new Set(finding.identifiers.filter(isVulnerabilityIdentifier).map(identifierKey));
}

function confidenceFor(score: number, exact: boolean): MatchExplanation["confidence"] {
  if (exact) return "exact";
  if (score >= 85) return "high";
  if (score >= 70) return "medium";
  if (score >= 50) return "low";
  return "none";
}

export function explainMatch(
  left: CanonicalFinding,
  right: CanonicalFinding,
  options: Partial<CorrelationOptions> = {},
): MatchExplanation {
  const resolved: CorrelationOptions = { ...defaultCorrelationOptions, ...options };
  const reasons: MatchReason[] = [];
  const blockers: MatchBlocker[] = [];
  let score = 0;
  let exact = false;

  const leftVulnerabilityIds = vulnerabilityIds(left);
  const rightVulnerabilityIds = vulnerabilityIds(right);
  const sharedIds = [...leftVulnerabilityIds].filter((value) => rightVulnerabilityIds.has(value));
  if (sharedIds.length > 0) {
    reasons.push({
      feature: "identifier",
      score: 40,
      message: `Shared vulnerability identifier${sharedIds.length > 1 ? "s" : ""}`,
      evidence: sharedIds,
    });
    score += 40;
  } else if (leftVulnerabilityIds.size > 0 && rightVulnerabilityIds.size > 0) {
    blockers.push({
      feature: "identifier",
      message: "Both findings have explicit but disjoint vulnerability identifiers.",
    });
  }

  const sharedFingerprints = fingerprintMatches(left, right);
  if (
    sharedFingerprints.length > 0 &&
    left.source.tool.toLowerCase() === right.source.tool.toLowerCase()
  ) {
    reasons.push({
      feature: "fingerprint",
      score: 55,
      message: "The same scanner supplied a stable fingerprint.",
      evidence: sharedFingerprints,
    });
    score += 55;
    exact = true;
  }

  const leftComponent = componentKey(left.component);
  const rightComponent = componentKey(right.component);
  if (leftComponent && rightComponent) {
    if (leftComponent === rightComponent) {
      reasons.push({
        feature: "component",
        score: 25,
        message: "Affected component identity matches.",
        evidence: [leftComponent],
      });
      score += 25;
    } else {
      const leftName = left.component?.name?.toLowerCase();
      const rightName = right.component?.name?.toLowerCase();
      if (leftName && rightName && leftName !== rightName) {
        blockers.push({
          feature: "component",
          message: `Affected components conflict (${leftName} versus ${rightName}).`,
        });
      }
    }
  }

  const leftAsset = assetKey(left.asset);
  const rightAsset = assetKey(right.asset);
  if (leftAsset && rightAsset) {
    if (leftAsset === rightAsset) {
      reasons.push({
        feature: "asset",
        score: 15,
        message: "Asset identity matches.",
        evidence: [leftAsset],
      });
      score += 15;
    } else if (resolved.scope === "instance") {
      blockers.push({
        feature: "asset",
        message: `Instance scope keeps different assets separate (${leftAsset} versus ${rightAsset}).`,
      });
    }
  }

  const leftPath = normalizePath(left.location?.uri ?? left.component?.path);
  const rightPath = normalizePath(right.location?.uri ?? right.component?.path);
  if (leftPath && rightPath && leftPath === rightPath) {
    const leftLine = left.location?.startLine;
    const rightLine = right.location?.startLine;
    const lineDistance =
      leftLine !== undefined && rightLine !== undefined
        ? Math.abs(leftLine - rightLine)
        : undefined;
    if (lineDistance === undefined || lineDistance <= resolved.lineWindow) {
      const locationScore = lineDistance === 0 ? 15 : 10;
      reasons.push({
        feature: "location",
        score: locationScore,
        message:
          lineDistance === undefined
            ? "File location matches."
            : `File location matches within ${lineDistance} line${lineDistance === 1 ? "" : "s"}.`,
        evidence: [leftPath],
      });
      score += locationScore;
    }
  }

  if (left.ruleId && right.ruleId && left.ruleId.toLowerCase() === right.ruleId.toLowerCase()) {
    reasons.push({
      feature: "rule",
      score: 10,
      message: "Scanner rule identifier matches.",
      evidence: [left.ruleId],
    });
    score += 10;
  }

  if (left.kind === right.kind) {
    reasons.push({
      feature: "kind",
      score: 5,
      message: `Both findings are ${left.kind} findings.`,
    });
    score += 5;
  } else if (
    left.kind !== "unknown" &&
    right.kind !== "unknown" &&
    !(["sca", "container"].includes(left.kind) && ["sca", "container"].includes(right.kind))
  ) {
    blockers.push({
      feature: "kind",
      message: `Finding kinds conflict (${left.kind} versus ${right.kind}).`,
    });
  }

  const titleSimilarity = jaccard(titleTokens(left.title), titleTokens(right.title));
  if (titleSimilarity >= 0.35) {
    const titleScore = Math.round(titleSimilarity * resolved.titleWeight);
    reasons.push({
      feature: "title",
      score: titleScore,
      message: `Titles share ${Math.round(titleSimilarity * 100)}% of meaningful tokens.`,
    });
    score += titleScore;
  }

  const hardBlocked = blockers.some(
    (blocker) =>
      blocker.feature === "component" || blocker.feature === "asset" || blocker.feature === "kind",
  );
  // Explicit, disjoint advisory IDs are a hard safety boundary. A shared package,
  // title, or scanner fingerprint is not enough to claim two different CVEs are one issue.
  const identifierBlocked = blockers.some((blocker) => blocker.feature === "identifier");
  const boundedScore = Math.min(100, Math.max(0, score));

  return {
    score: boundedScore,
    confidence: confidenceFor(boundedScore, exact),
    matched: !hardBlocked && !identifierBlocked && boundedScore >= resolved.threshold,
    reasons: reasons.sort((a, b) => b.score - a.score),
    blockers,
  };
}

import type {
  CanonicalFinding,
  FindingAsset,
  FindingComponent,
  FindingIdentifier,
  FindingKind,
  FindingLocation,
  FindingRemediation,
  FindingSource,
  FindingSuppression,
  JsonValue,
  Severity,
} from "../model.js";
import { uniqueIdentifiers } from "../identifiers.js";
import { canonicalizePurl, normalizePath, stableHash, uniqueBy } from "../utils.js";

export interface FindingSeed {
  source: FindingSource;
  kind?: FindingKind | undefined;
  title: string;
  description?: string | undefined;
  severity?: Severity | undefined;
  identifiers?: FindingIdentifier[] | undefined;
  component?: FindingComponent | undefined;
  asset?: FindingAsset | undefined;
  location?: FindingLocation | undefined;
  ruleId?: string | undefined;
  fingerprints?: Record<string, string> | undefined;
  remediation?: FindingRemediation | undefined;
  suppressed?: boolean | undefined;
  suppressions?: FindingSuppression[] | undefined;
  references?: string[] | undefined;
  properties?: Record<string, JsonValue> | undefined;
  nativeId?: string | undefined;
}

export function makeFinding(seed: FindingSeed): CanonicalFinding {
  const component = normalizeComponent(seed.component);
  const location = normalizeLocation(seed.location);
  const references = uniqueBy(seed.references ?? [], (value) => value).sort();
  const identifiers = uniqueIdentifiers(seed.identifiers ?? []);
  const identity = [
    seed.source.tool.toLowerCase(),
    seed.source.report,
    seed.nativeId ?? "",
    ...identifiers.map((identifier) => `${identifier.scheme}:${identifier.value}`).sort(),
    component?.purl ?? component?.name ?? "",
    seed.asset?.key ?? seed.asset?.name ?? "",
    location?.uri ?? "",
    location?.startLine?.toString() ?? "",
    seed.ruleId ?? "",
    seed.title,
  ].join("|");

  return {
    id: `finding-${stableHash(identity)}`,
    source: seed.source,
    kind: seed.kind ?? "unknown",
    title: seed.title,
    ...(seed.description ? { description: seed.description } : {}),
    severity: seed.severity ?? "unknown",
    identifiers,
    ...(component ? { component } : {}),
    ...(seed.asset ? { asset: seed.asset } : {}),
    ...(location ? { location } : {}),
    ...(seed.ruleId ? { ruleId: seed.ruleId } : {}),
    fingerprints: cleanStrings(seed.fingerprints ?? {}),
    ...(seed.remediation && (seed.remediation.fixedVersion || seed.remediation.recommendation)
      ? { remediation: seed.remediation }
      : {}),
    ...(seed.suppressed !== undefined ? { suppressed: seed.suppressed } : {}),
    ...(seed.suppressions ? { suppressions: seed.suppressions } : {}),
    references,
    properties: seed.properties ?? {},
  };
}

function normalizeComponent(component: FindingComponent | undefined): FindingComponent | undefined {
  if (!component) return undefined;
  const purl = canonicalizePurl(component.purl);
  const normalized = {
    ...(purl ? { purl } : {}),
    ...(component.ecosystem ? { ecosystem: component.ecosystem } : {}),
    ...(component.name ? { name: component.name } : {}),
    ...(component.version ? { version: component.version } : {}),
    ...(component.path ? { path: normalizePath(component.path) ?? component.path } : {}),
    ...(component.type ? { type: component.type } : {}),
  };
  return Object.keys(normalized).length > 0 ? normalized : undefined;
}

function normalizeLocation(location: FindingLocation | undefined): FindingLocation | undefined {
  if (!location) return undefined;
  const normalized = {
    ...(location.uri ? { uri: normalizePath(location.uri) ?? location.uri } : {}),
    ...(location.startLine !== undefined ? { startLine: location.startLine } : {}),
    ...(location.endLine !== undefined ? { endLine: location.endLine } : {}),
    ...(location.startColumn !== undefined ? { startColumn: location.startColumn } : {}),
    ...(location.symbol ? { symbol: location.symbol } : {}),
  };
  return Object.keys(normalized).length > 0 ? normalized : undefined;
}

export function cleanStrings(values: Record<string, string | undefined>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(values).filter((entry): entry is [string, string] => Boolean(entry[1])),
  );
}

export function source(
  tool: string,
  report: string,
  version?: string,
  run?: string,
): FindingSource {
  return {
    tool,
    report,
    ...(version ? { version } : {}),
    ...(run ? { run } : {}),
  };
}

export function asset(
  type: FindingAsset["type"],
  name: string | undefined,
): FindingAsset | undefined {
  return name ? { type, name, key: name.toLowerCase() } : undefined;
}

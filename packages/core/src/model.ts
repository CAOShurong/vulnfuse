export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export const severityOrder = ["unknown", "info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof severityOrder)[number];

export type FindingKind =
  "sca" | "sast" | "container" | "iac" | "secret" | "dast" | "license" | "unknown";

export type ReportFormat =
  | "sarif"
  | "trivy"
  | "grype"
  | "snyk"
  | "cyclonedx"
  | "openvex"
  | "osv-scanner"
  | "csv"
  | "vulnfuse"
  | "unknown";

export interface FindingSource {
  tool: string;
  report: string;
  version?: string;
  run?: string;
}

export interface FindingIdentifier {
  scheme: string;
  value: string;
  relationship: "primary" | "alias" | "related" | "weakness" | "rule";
}

export interface FindingComponent {
  purl?: string;
  ecosystem?: string;
  name?: string;
  version?: string;
  path?: string;
  type?: string;
}

export interface FindingAsset {
  type: "repository" | "image" | "host" | "file" | "application" | "unknown";
  name: string;
  key?: string;
}

export interface FindingLocation {
  uri?: string;
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  symbol?: string;
}

export interface FindingRemediation {
  fixedVersion?: string;
  recommendation?: string;
}

export type FindingSuppressionKind = "inSource" | "external";
export type FindingSuppressionStatus = "accepted" | "underReview" | "rejected";

export interface FindingSuppression {
  kind: FindingSuppressionKind;
  status?: FindingSuppressionStatus;
  justification?: string;
}

export interface CanonicalFinding {
  id: string;
  source: FindingSource;
  kind: FindingKind;
  title: string;
  description?: string;
  severity: Severity;
  identifiers: FindingIdentifier[];
  component?: FindingComponent;
  asset?: FindingAsset;
  location?: FindingLocation;
  ruleId?: string;
  fingerprints: Record<string, string>;
  remediation?: FindingRemediation;
  suppressed?: boolean;
  nonFinding?: boolean;
  suppressions?: FindingSuppression[];
  references: string[];
  properties: Record<string, JsonValue>;
}

export interface ParseWarning {
  code: string;
  message: string;
  path?: string;
}

export interface ParsedReport {
  format: ReportFormat;
  sourceName: string;
  tool: string;
  tools?: string[];
  toolVersions?: Record<string, string[]>;
  findings: CanonicalFinding[];
  warnings: ParseWarning[];
  metadata: Record<string, JsonValue>;
}

export interface ReportInput {
  name: string;
  content: string;
}

export type MatchScope = "instance" | "root-cause";
export type OutputFormat = "json" | "sarif" | "csv" | "markdown" | "html";

export interface CorrelationOptions {
  threshold: number;
  scope: MatchScope;
  lineWindow: number;
  titleWeight: number;
}

export interface MatchReason {
  feature:
    "identifier" | "fingerprint" | "component" | "asset" | "location" | "rule" | "title" | "kind";
  score: number;
  message: string;
  evidence?: string[];
}

export interface MatchBlocker {
  feature: "identifier" | "component" | "asset" | "kind";
  message: string;
}

export interface MatchExplanation {
  score: number;
  confidence: "none" | "low" | "medium" | "high" | "exact";
  matched: boolean;
  reasons: MatchReason[];
  blockers: MatchBlocker[];
}

export interface ClusterEdge {
  leftId: string;
  rightId: string;
  explanation: MatchExplanation;
}

export interface FindingCluster {
  id: string;
  primary: CanonicalFinding;
  members: CanonicalFinding[];
  severity: Severity;
  suppressed: boolean;
  nonFinding: boolean;
  sourceTools: string[];
  identifiers: FindingIdentifier[];
  assets: FindingAsset[];
  confidence: MatchExplanation["confidence"];
  edges: ClusterEdge[];
}

export type FindingDisposition = "active" | "suppressed" | "non-finding";

export function clusterDisposition(
  cluster: Pick<FindingCluster, "suppressed" | "nonFinding">,
): FindingDisposition {
  if (cluster.nonFinding) return "non-finding";
  if (cluster.suppressed) return "suppressed";
  return "active";
}

export interface ToolCoverage {
  tool: string;
  reports: number;
  sourceFindings: number;
  clusters: number;
  exclusiveClusters: number;
  sharedClusters: number;
}

export interface ToolPairCoverage {
  leftTool: string;
  rightTool: string;
  sharedClusters: number;
  unionClusters: number;
  overlapRatio: number;
}

export interface CoverageSummary {
  singleToolClusters: number;
  multiToolClusters: number;
  tools: ToolCoverage[];
  pairs: ToolPairCoverage[];
  pairwiseOmitted: boolean;
}

export interface CorrelationSummary {
  inputReports: number;
  inputFindings: number;
  clusters: number;
  activeClusters: number;
  suppressedClusters: number;
  nonFindingClusters: number;
  duplicatesCollapsed: number;
  sourceTools: string[];
  bySeverity: Record<Severity, number>;
  activeBySeverity: Record<Severity, number>;
  suppressedBySeverity: Record<Severity, number>;
  nonFindingBySeverity: Record<Severity, number>;
  byKind: Record<FindingKind, number>;
  coverage: CoverageSummary;
}

export interface CorrelationResult {
  schemaVersion: "1.0";
  options: CorrelationOptions;
  reports: Array<{
    name: string;
    format: ReportFormat;
    tool: string;
    tools: string[];
    toolVersions: Record<string, string[]>;
    findings: number;
    warnings: ParseWarning[];
    metadata: Record<string, JsonValue>;
  }>;
  clusters: FindingCluster[];
  rejectedCandidates: ClusterEdge[];
  summary: CorrelationSummary;
}

export type BaselineState = "new" | "unchanged" | "updated" | "absent";

export interface BaselineDiffItem {
  state: BaselineState;
  cluster: FindingCluster;
  baselineCluster?: FindingCluster;
  explanation?: MatchExplanation;
  changedFields: string[];
}

export interface BaselineDiffSummary {
  baselineClusters: number;
  currentClusters: number;
  new: number;
  updated: number;
  unchanged: number;
  absent: number;
  newBySeverity: Record<Severity, number>;
  newActiveBySeverity: Record<Severity, number>;
}

export interface ScanSetReportCountChange {
  tool: string;
  baseline: number;
  current: number;
}

export interface ScanSetToolVersionEvidence {
  versions: string[];
  unversionedReports: number;
}

export interface ScanSetToolVersionChange {
  tool: string;
  baseline: ScanSetToolVersionEvidence;
  current: ScanSetToolVersionEvidence;
}

export interface ScanSetChange {
  detected: boolean;
  addedTools: string[];
  removedTools: string[];
  changedReportCounts: ScanSetReportCountChange[];
  changedToolVersions: ScanSetToolVersionChange[];
}

export interface BaselineDiffResult {
  schemaVersion: "1.0";
  options: CorrelationOptions;
  baselineSummary: CorrelationSummary;
  currentSummary: CorrelationSummary;
  baselineReports: CorrelationResult["reports"];
  currentReports: CorrelationResult["reports"];
  scanSetChange: ScanSetChange;
  items: BaselineDiffItem[];
  summary: BaselineDiffSummary;
}

export const defaultCorrelationOptions: CorrelationOptions = {
  threshold: 70,
  scope: "instance",
  lineWindow: 5,
  titleWeight: 10,
};

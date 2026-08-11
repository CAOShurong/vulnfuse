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
  sourceTools: string[];
  identifiers: FindingIdentifier[];
  assets: FindingAsset[];
  confidence: MatchExplanation["confidence"];
  edges: ClusterEdge[];
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
  duplicatesCollapsed: number;
  sourceTools: string[];
  bySeverity: Record<Severity, number>;
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
    findings: number;
    warnings: ParseWarning[];
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
}

export interface ScanSetReportCountChange {
  tool: string;
  baseline: number;
  current: number;
}

export interface ScanSetChange {
  detected: boolean;
  addedTools: string[];
  removedTools: string[];
  changedReportCounts: ScanSetReportCountChange[];
}

export interface BaselineDiffResult {
  schemaVersion: "1.0";
  options: CorrelationOptions;
  baselineSummary: CorrelationSummary;
  currentSummary: CorrelationSummary;
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

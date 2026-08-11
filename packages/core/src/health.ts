import type { ParseWarning } from "./model.js";

const incompleteReportWarningCodes = new Set([
  "sarif.execution-failed",
  "sarif.execution-status-unknown",
  "sarif.external-results-unsupported",
  "sarif.invalid-invocation",
  "sarif.invalid-results",
  "sarif.results-unavailable",
  "sarif.tool-configuration-error",
  "sarif.tool-execution-error",
]);

export function isIncompleteReportWarning(warning: ParseWarning): boolean {
  return incompleteReportWarningCodes.has(warning.code);
}

export function countIncompleteReports(
  reports: ReadonlyArray<{ warnings: ReadonlyArray<ParseWarning> }>,
): number {
  return reports.filter((report) => report.warnings.some(isIncompleteReportWarning)).length;
}

import type { CorrelationResult, ExportOptions, OutputFormat } from "../model.js";
import { exportBaselineDiff } from "./baseline.js";
import { exportCsv } from "./csv.js";
import { exportBaselineHtml, exportHtml } from "./html.js";
import { exportJson } from "./json.js";
import { exportMarkdown } from "./markdown.js";
import { exportSarif } from "./sarif.js";

export function exportCorrelation(
  result: CorrelationResult,
  format: OutputFormat,
  options: ExportOptions = {},
): string {
  if (options.sarifFallbackLocation !== undefined && format !== "sarif") {
    throw new Error("SARIF fallback location can only be used with SARIF output.");
  }
  switch (format) {
    case "json":
      return exportJson(result);
    case "sarif":
      return exportSarif(result, options);
    case "csv":
      return exportCsv(result);
    case "markdown":
      return exportMarkdown(result);
    case "html":
      return exportHtml(result);
  }
}

export {
  exportBaselineDiff,
  exportBaselineHtml,
  exportCsv,
  exportHtml,
  exportJson,
  exportMarkdown,
  exportSarif,
};
export { validateSarifFallbackLocation } from "./sarif-host.js";

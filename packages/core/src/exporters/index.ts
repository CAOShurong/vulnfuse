import type { CorrelationResult, OutputFormat } from "../model.js";
import { exportBaselineDiff } from "./baseline.js";
import { exportCsv } from "./csv.js";
import { exportBaselineHtml, exportHtml } from "./html.js";
import { exportJson } from "./json.js";
import { exportMarkdown } from "./markdown.js";
import { exportSarif } from "./sarif.js";

export function exportCorrelation(result: CorrelationResult, format: OutputFormat): string {
  switch (format) {
    case "json":
      return exportJson(result);
    case "sarif":
      return exportSarif(result);
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

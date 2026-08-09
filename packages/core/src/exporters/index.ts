import type { CorrelationResult } from "../model.js";
import { exportCsv } from "./csv.js";
import { exportJson } from "./json.js";
import { exportMarkdown } from "./markdown.js";
import { exportSarif } from "./sarif.js";

export type OutputFormat = "json" | "sarif" | "csv" | "markdown";

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
  }
}

export { exportCsv, exportJson, exportMarkdown, exportSarif };

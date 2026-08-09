import type { CorrelationResult } from "../model.js";

export function exportJson(result: CorrelationResult): string {
  return `${JSON.stringify(result, null, 2)}\n`;
}

import { PackageURL } from "packageurl-js";

import type { JsonValue, Severity } from "./model.js";
import { severityOrder } from "./model.js";

export function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

export function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

export function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return undefined;
}

export function asNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

export function asJsonValue(value: unknown): JsonValue | undefined {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (Array.isArray(value)) {
    return value.map(asJsonValue).filter((item): item is JsonValue => item !== undefined);
  }
  const record = asRecord(value);
  if (!record) return undefined;
  const output: Record<string, JsonValue> = {};
  for (const [key, item] of Object.entries(record)) {
    const normalized = asJsonValue(item);
    if (normalized !== undefined) output[key] = normalized;
  }
  return output;
}

export function normalizeWhitespace(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

export function normalizeSeverity(value: unknown): Severity {
  const text = asString(value)?.toLowerCase();
  if (!text) return "unknown";
  if (["critical", "blocker", "error", "very_high", "very-high"].includes(text)) return "critical";
  if (["high", "important"].includes(text)) return "high";
  if (["medium", "moderate", "warning", "warn"].includes(text)) return "medium";
  if (["low", "minor", "note"].includes(text)) return "low";
  if (["info", "informational", "none", "negligible"].includes(text)) return "info";

  const numeric = Number(text);
  if (Number.isFinite(numeric)) {
    if (numeric >= 9) return "critical";
    if (numeric >= 7) return "high";
    if (numeric >= 4) return "medium";
    if (numeric > 0) return "low";
    return "info";
  }
  return "unknown";
}

export function maxSeverity(values: Severity[]): Severity {
  return values.reduce<Severity>(
    (highest, current) =>
      severityOrder.indexOf(current) > severityOrder.indexOf(highest) ? current : highest,
    "unknown",
  );
}

export function normalizePath(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const withoutQuery = value.split(/[?#]/, 1)[0] ?? value;
  return decodeURIComponentSafe(withoutQuery)
    .replace(/^file:\/\//i, "")
    .replace(/\\/g, "/")
    .replace(/^\.\//, "")
    .replace(/\/{2,}/g, "/")
    .replace(/^\/[A-Za-z]:\//, (match) => match.slice(1))
    .toLowerCase();
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function canonicalizePurl(value: string | undefined): string | undefined {
  if (!value) return undefined;
  try {
    return PackageURL.fromString(value).toString();
  } catch {
    return undefined;
  }
}

export function componentKey(
  component:
    | {
        purl?: string;
        ecosystem?: string;
        name?: string;
        version?: string;
      }
    | undefined,
): string | undefined {
  if (!component) return undefined;
  const purl = canonicalizePurl(component.purl);
  if (purl) return purl.toLowerCase();
  if (!component.name) return undefined;
  return [component.ecosystem ?? "", component.name, component.version ?? ""]
    .map((part) => part.trim().toLowerCase())
    .join(":");
}

export function assetKey(
  asset: { type: string; name: string; key?: string } | undefined,
): string | undefined {
  if (!asset) return undefined;
  return `${asset.type}:${asset.key ?? asset.name}`.trim().toLowerCase();
}

export function stableHash(value: string): string {
  let hash = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (const byte of new TextEncoder().encode(value)) {
    hash ^= BigInt(byte);
    hash = BigInt.asUintN(64, hash * prime);
  }
  return hash.toString(36).padStart(13, "0");
}

export function uniqueBy<T>(values: T[], key: (value: T) => string): T[] {
  const seen = new Set<string>();
  return values.filter((value) => {
    const candidate = key(value);
    if (seen.has(candidate)) return false;
    seen.add(candidate);
    return true;
  });
}

export function safeHttpReference(value: unknown): string | undefined {
  const text = asString(value);
  if (!text) return undefined;
  try {
    const url = new URL(text);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : undefined;
  } catch {
    return undefined;
  }
}

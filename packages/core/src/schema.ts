import { z } from "zod";

z.config({ jitless: true });

const jsonValueSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    z.string(),
    z.number(),
    z.boolean(),
    z.null(),
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ]),
);

export const canonicalFindingSchema = z.object({
  id: z.string().min(1),
  source: z.object({
    tool: z.string().min(1),
    report: z.string().min(1),
    version: z.string().optional(),
    run: z.string().optional(),
  }),
  kind: z.enum(["sca", "sast", "container", "iac", "secret", "dast", "license", "unknown"]),
  title: z.string().min(1),
  description: z.string().optional(),
  severity: z.enum(["unknown", "info", "low", "medium", "high", "critical"]),
  identifiers: z.array(
    z.object({
      scheme: z.string().min(1),
      value: z.string().min(1),
      relationship: z.enum(["primary", "alias", "related", "weakness", "rule"]),
    }),
  ),
  component: z
    .object({
      purl: z.string().optional(),
      ecosystem: z.string().optional(),
      name: z.string().optional(),
      version: z.string().optional(),
      path: z.string().optional(),
      type: z.string().optional(),
    })
    .optional(),
  asset: z
    .object({
      type: z.enum(["repository", "image", "host", "file", "application", "unknown"]),
      name: z.string(),
      key: z.string().optional(),
    })
    .optional(),
  location: z
    .object({
      uri: z.string().optional(),
      startLine: z.number().int().positive().optional(),
      endLine: z.number().int().positive().optional(),
      startColumn: z.number().int().positive().optional(),
      symbol: z.string().optional(),
    })
    .optional(),
  ruleId: z.string().optional(),
  fingerprints: z.record(z.string(), z.string()),
  remediation: z
    .object({
      fixedVersion: z.string().optional(),
      recommendation: z.string().optional(),
    })
    .optional(),
  suppressed: z.boolean().optional(),
  nonFinding: z.boolean().optional(),
  suppressions: z
    .array(
      z.object({
        kind: z.enum(["inSource", "external"]),
        status: z.enum(["accepted", "underReview", "rejected"]).optional(),
        justification: z.string().optional(),
      }),
    )
    .optional(),
  references: z.array(z.string()),
  properties: z.record(z.string(), jsonValueSchema),
});

export const vulnfuseDocumentSchema = z.object({
  schemaVersion: z.literal("1.0"),
  options: z.object({
    threshold: z.number().min(0).max(100),
    scope: z.enum(["instance", "root-cause"]),
    lineWindow: z.number().int().nonnegative(),
    titleWeight: z.number().min(0).max(25),
  }),
  reports: z.array(z.unknown()),
  clusters: z.array(z.unknown()),
  rejectedCandidates: z.array(z.unknown()).optional(),
  summary: z.unknown(),
});

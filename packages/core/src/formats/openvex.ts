import { normalizeIdentifier, uniqueIdentifiers } from "../identifiers.js";
import type {
  CanonicalFinding,
  FindingAsset,
  FindingIdentifier,
  FindingKind,
  JsonValue,
  ParsedReport,
} from "../model.js";
import {
  asArray,
  asJsonValue,
  asNumber,
  asRecord,
  asString,
  canonicalizePurl,
  safeHttpReference,
} from "../utils.js";
import { asset, makeFinding, source } from "./common.js";

const openVexStatuses = new Set(["not_affected", "affected", "fixed", "under_investigation"]);

interface OpenVexSubject {
  id?: string;
  purl?: string;
  raw?: JsonValue;
}

export function parseOpenVex(root: Record<string, unknown>, reportName: string): ParsedReport {
  const findings: CanonicalFinding[] = [];
  const warnings: ParsedReport["warnings"] = [];
  const author = asString(root["author"]);
  const toolName = author ? `OpenVEX (${author})` : "OpenVEX";
  const documentId = asString(root["@id"]);
  const documentTimestamp = asString(root["timestamp"]);
  const statements = asArray(root["statements"]);

  for (const [statementIndex, statementValue] of statements.entries()) {
    const statement = asRecord(statementValue);
    if (!statement) {
      warnings.push({
        code: "openvex.invalid-statement",
        message: "An OpenVEX statement was not an object and was ignored.",
        path: `statements[${statementIndex}]`,
      });
      continue;
    }

    const vulnerability = asRecord(statement["vulnerability"]);
    const vulnerabilityName = asString(vulnerability?.["name"]);
    if (!vulnerabilityName) {
      warnings.push({
        code: "openvex.missing-vulnerability",
        message: "An OpenVEX statement had no vulnerability name and was ignored.",
        path: `statements[${statementIndex}].vulnerability.name`,
      });
      continue;
    }

    const products = asArray(statement["products"]);
    if (products.length === 0) {
      warnings.push({
        code: "openvex.no-products",
        message:
          "An OpenVEX statement had no in-document products. Encapsulating-document inheritance is not resolved, so the statement was ignored.",
        path: `statements[${statementIndex}].products`,
      });
      continue;
    }

    const rawStatus = statement["status"];
    const status = asString(rawStatus);
    if (!status || !openVexStatuses.has(status)) {
      warnings.push({
        code: "openvex.invalid-status",
        message:
          "An OpenVEX status was missing or invalid. Its evidence remains active and no disposition is inferred.",
        path: `statements[${statementIndex}].status`,
      });
    }
    if (
      status === "not_affected" &&
      !asString(statement["justification"]) &&
      !asString(statement["impact_statement"])
    ) {
      warnings.push({
        code: "openvex.incomplete-not-affected",
        message:
          "A not_affected OpenVEX statement had neither justification nor impact_statement. Its evidence remains active.",
        path: `statements[${statementIndex}]`,
      });
    }
    if (status === "affected" && !asString(statement["action_statement"])) {
      warnings.push({
        code: "openvex.incomplete-affected",
        message:
          "An affected OpenVEX statement had no action_statement. Its evidence remains active.",
        path: `statements[${statementIndex}]`,
      });
    }

    const identifiers = vulnerabilityIdentifiers(vulnerabilityName, vulnerability);
    const vulnerabilityDescription = asString(vulnerability?.["description"]);
    const statementId = asString(statement["@id"]);

    for (const [productIndex, productValue] of products.entries()) {
      const product = subject(
        productValue,
        `statements[${statementIndex}].products[${productIndex}]`,
        warnings,
      );
      if (!product) continue;
      const productRecord = asRecord(productValue);
      const subcomponents = asArray(productRecord?.["subcomponents"]);
      if (subcomponents.length === 0) {
        findings.push(
          openVexFinding({
            toolName,
            reportName,
            statement,
            statementIndex,
            productIndex,
            vulnerabilityName,
            vulnerabilityDescription,
            identifiers,
            status,
            product,
            component: product,
            statementId,
            documentId,
            documentTimestamp,
          }),
        );
        continue;
      }

      for (const [subcomponentIndex, subcomponentValue] of subcomponents.entries()) {
        const component = subject(
          subcomponentValue,
          `statements[${statementIndex}].products[${productIndex}].subcomponents[${subcomponentIndex}]`,
          warnings,
        );
        if (!component) continue;
        findings.push(
          openVexFinding({
            toolName,
            reportName,
            statement,
            statementIndex,
            productIndex,
            subcomponentIndex,
            vulnerabilityName,
            vulnerabilityDescription,
            identifiers,
            status,
            product,
            component,
            statementId,
            documentId,
            documentTimestamp,
          }),
        );
      }
    }
  }

  if (statements.length === 0) {
    warnings.push({
      code: "openvex.no-statements",
      message: "The OpenVEX document has no statements.",
      path: "statements",
    });
  }

  return {
    format: "openvex",
    sourceName: reportName,
    tool: toolName,
    tools: [toolName],
    findings,
    warnings,
    metadata: jsonRecord({
      context: root["@context"],
      documentId,
      author,
      role: root["role"],
      timestamp: root["timestamp"],
      lastUpdated: root["last_updated"],
      version: asNumber(root["version"]),
      tooling: root["tooling"],
    }),
  };
}

function subject(
  value: unknown,
  path: string,
  warnings: ParsedReport["warnings"],
): OpenVexSubject | undefined {
  const record = asRecord(value);
  if (!record) {
    warnings.push({
      code: "openvex.invalid-product",
      message: "An OpenVEX product or subcomponent was not an object and was ignored.",
      path,
    });
    return undefined;
  }
  const id = asString(record["@id"]);
  const identifiers = asRecord(record["identifiers"]);
  const declaredPurl = asString(identifiers?.["purl"]);
  const declaredCanonical = canonicalizePurl(declaredPurl);
  const idCanonical = canonicalizePurl(id);
  const purl = declaredCanonical ?? idCanonical;
  const raw = asJsonValue(record);
  if (declaredPurl && !declaredCanonical) {
    warnings.push({
      code: "openvex.invalid-purl",
      message:
        "An OpenVEX identifiers.purl value was invalid and was not used as package identity.",
      path: `${path}.identifiers.purl`,
    });
  }
  if (!id && !declaredPurl && Object.keys(asRecord(record["hashes"]) ?? {}).length === 0) {
    warnings.push({
      code: "openvex.unidentified-product",
      message: "An OpenVEX product or subcomponent had no usable identifier and was ignored.",
      path,
    });
    return undefined;
  }
  return {
    ...(id ? { id } : {}),
    ...(purl ? { purl } : {}),
    ...(raw !== undefined ? { raw } : {}),
  };
}

function vulnerabilityIdentifiers(
  vulnerabilityName: string,
  vulnerability: Record<string, unknown> | undefined,
): FindingIdentifier[] {
  const identifiers: FindingIdentifier[] = [];
  const primary = normalizeIdentifier(vulnerabilityName, "primary");
  if (primary) identifiers.push(primary);
  for (const aliasValue of asArray(vulnerability?.["aliases"])) {
    const alias = asString(aliasValue);
    if (!alias) continue;
    const identifier = normalizeIdentifier(alias, "alias");
    if (identifier) identifiers.push(identifier);
  }
  return uniqueIdentifiers(identifiers);
}

function openVexFinding(input: {
  toolName: string;
  reportName: string;
  statement: Record<string, unknown>;
  statementIndex: number;
  productIndex: number;
  subcomponentIndex?: number;
  vulnerabilityName: string;
  vulnerabilityDescription: string | undefined;
  identifiers: FindingIdentifier[];
  status: string | undefined;
  product: OpenVexSubject;
  component: OpenVexSubject;
  statementId: string | undefined;
  documentId: string | undefined;
  documentTimestamp: string | undefined;
}): CanonicalFinding {
  const componentIdentity = input.component.purl ?? input.component.id;
  const productIdentity = input.product.purl ?? input.product.id;
  const statusLabel = input.status ?? "unknown";
  const actionStatement = asString(input.statement["action_statement"]);
  return makeFinding({
    source: source(input.toolName, input.reportName),
    kind: findingKind(input.component.purl ?? input.product.purl),
    title: `${input.vulnerabilityName} for ${componentIdentity ?? productIdentity ?? "unidentified product"} (OpenVEX: ${statusLabel})`,
    ...(input.vulnerabilityDescription ? { description: input.vulnerabilityDescription } : {}),
    severity: "unknown",
    identifiers: input.identifiers,
    ...(input.component.purl ? { component: { purl: input.component.purl } } : {}),
    ...(productAsset(input.product) ? { asset: productAsset(input.product) } : {}),
    ...(actionStatement ? { remediation: { recommendation: actionStatement } } : {}),
    suppressed: false,
    nonFinding: false,
    references: [
      safeHttpReference(asRecord(input.statement["vulnerability"])?.["@id"]),
      safeHttpReference(input.statementId),
      safeHttpReference(input.documentId),
    ].filter((value): value is string => Boolean(value)),
    properties: jsonRecord({
      "openvex.status": input.statement["status"],
      "openvex.justification": input.statement["justification"],
      "openvex.statusNotes": input.statement["status_notes"],
      "openvex.impactStatement": input.statement["impact_statement"],
      "openvex.actionStatement": input.statement["action_statement"],
      "openvex.actionStatementTimestamp": input.statement["action_statement_timestamp"],
      "openvex.statementTimestamp": input.statement["timestamp"] ?? input.documentTimestamp,
      "openvex.product": input.product.raw,
      "openvex.subcomponent":
        input.subcomponentIndex === undefined ? undefined : input.component.raw,
    }),
    nativeId: `${input.statementIndex}:${input.productIndex}:${input.subcomponentIndex ?? "product"}`,
  });
}

function findingKind(purl: string | undefined): FindingKind {
  const type = purl?.slice(4).split("/", 1)[0]?.toLowerCase();
  return type === "oci" || type === "docker" ? "container" : "sca";
}

function productAsset(product: OpenVexSubject): FindingAsset | undefined {
  const name = product.purl ?? product.id;
  if (!name) return undefined;
  const kind = findingKind(product.purl);
  return asset(kind === "container" ? "image" : "application", name);
}

function jsonRecord(values: Record<string, unknown>): Record<string, JsonValue> {
  return Object.fromEntries(
    Object.entries(values)
      .map(([key, value]) => [key, asJsonValue(value)] as const)
      .filter((entry): entry is readonly [string, JsonValue] => entry[1] !== undefined),
  );
}

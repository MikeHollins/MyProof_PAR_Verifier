import { z } from "zod";

import {
  CHECK_IDS,
  CHECK_VARIANTS,
  LIMITATION_CODES,
  MAX_REPORT_LIMITATIONS,
  MAX_REPORT_REASONS,
} from "./constants.js";
import { CheckSchema } from "./check.js";
import { VerifyProofAssetInputSchema } from "./input.js";
import { PublicRecordCoherenceReportSchema } from "./report.js";

type JsonObject = Record<string, unknown>;
type JsonSchemaDocument = JsonObject & {
  $defs?: Record<string, JsonObject>;
};

const REPORT_SCHEMA_NAME = "myproof.par.public-record-coherence.v1";
const CHECK_SCHEMA_NAME = "myproof.par.public-record-check.v1";

function asObject(value: unknown): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("generated schema has an unexpected non-object node");
  }
  return value as JsonObject;
}

function asProperties(value: JsonObject): JsonObject {
  return asObject(value.properties);
}

function addDateTimeFormat(definition: JsonObject): void {
  const pattern = definition.pattern;
  if (typeof pattern === "string" && pattern.includes("\\d{4}") && pattern.includes("T")) {
    // Format validation is consumer-configurable in JSON Schema; the runtime
    // Zod contract remains authoritative when a host ignores annotations.
    definition.format = "date-time";
  }
}

function addDateTimeFormats(document: JsonSchemaDocument): void {
  for (const definition of Object.values(document.$defs ?? {})) addDateTimeFormat(definition);
}

function variantSchema(
  variant: (typeof CHECK_VARIANTS)[(typeof CHECK_IDS)[number]][number],
): JsonObject {
  const properties = Object.fromEntries([
    ["id", { const: variant.id }],
    ["state", { const: variant.state }],
    ["reason_code", { const: variant.reason_code }],
    ["verification_method", { const: variant.verification_method }],
    ["authority", { const: variant.authority }],
    ["required", { const: variant.required }],
  ]);
  return {
    type: "object",
    properties,
    required: Object.keys(properties),
    additionalProperties: false,
  };
}

function addCheckStaticConstraints(document: JsonSchemaDocument): void {
  const definitions = document.$defs;
  if (!definitions) throw new Error("generated schema has no definitions");
  const check = definitions[CHECK_SCHEMA_NAME];
  if (!check) throw new Error("generated schema has no check definition");

  definitions[CHECK_SCHEMA_NAME] = {
    oneOf: CHECK_IDS.flatMap((id) => CHECK_VARIANTS[id].map(variantSchema)),
    title: check.title,
    description: check.description,
  };
}

function requiredStateSchema(states: readonly string[]): JsonObject {
  return {
    type: "object",
    properties: {
      required: { const: true },
      state: { enum: states },
    },
    required: ["required", "state"],
  };
}

function conditionSchema(condition: string): JsonObject {
  return {
    properties: { registry_active_condition: { const: condition } },
    required: ["registry_active_condition"],
  };
}

function addReportStaticConstraints(document: JsonSchemaDocument): void {
  const definitions = document.$defs;
  if (!definitions) throw new Error("generated report schema has no definitions");
  const report = definitions[REPORT_SCHEMA_NAME];
  if (!report) throw new Error("generated report schema has no report definition");

  const reportProperties = asProperties(report);
  const checks = asObject(reportProperties.checks);
  checks.minItems = CHECK_IDS.length;
  checks.maxItems = CHECK_IDS.length;
  checks.prefixItems = CHECK_IDS.map((id) => ({
    type: "object",
    properties: { id: { const: id } },
    required: ["id"],
  }));

  for (const field of ["warnings", "errors", "limitations"]) {
    asObject(reportProperties[field]).uniqueItems = true;
  }

  const limitations = asObject(reportProperties.limitations);
  limitations.minItems = LIMITATION_CODES.length;
  limitations.maxItems = LIMITATION_CODES.length;
  limitations.prefixItems = LIMITATION_CODES.map((code) => ({ const: code }));

  const requiredCheck = {
    type: "object",
    properties: { required: { const: true } },
    required: ["required"],
  };
  const requiredFailure = requiredStateSchema(["FAIL"]);
  const allOf: JsonObject[] = [
    {
      properties: {
        checks: { contains: requiredCheck },
      },
    },
    {
      if: {
        properties: { record_coherence: { const: "COHERENT" } },
        required: ["record_coherence"],
      },
      then: {
        properties: {
          checks: { not: { contains: requiredStateSchema(["FAIL", "UNKNOWN", "NOT_ASSESSED"]) } },
        },
      },
    },
    {
      if: {
        properties: { record_coherence: { const: "CONTRADICTORY" } },
        required: ["record_coherence"],
      },
      then: { properties: { checks: { contains: requiredFailure } } },
    },
    {
      if: {
        properties: { record_coherence: { const: "INDETERMINATE" } },
        required: ["record_coherence"],
      },
      then: {
        properties: {
          checks: {
            allOf: [
              { not: { contains: requiredFailure } },
              { contains: requiredStateSchema(["UNKNOWN", "NOT_ASSESSED"]) },
            ],
          },
        },
      },
    },
    {
      if: conditionSchema("SATISFIED"),
      then: {
        properties: {
          record_coherence: { const: "COHERENT" },
          registry_status: { const: "ACTIVE" },
        },
      },
    },
    {
      if: conditionSchema("NOT_SATISFIED"),
      then: {
        properties: {
          record_coherence: { const: "COHERENT" },
          registry_status: { enum: ["REVOKED", "SUSPENDED"] },
        },
      },
    },
    {
      if: {
        properties: {
          record_coherence: { const: "COHERENT" },
          registry_status: { const: "ACTIVE" },
        },
      },
      then: { properties: { registry_active_condition: { enum: ["NOT_REQUESTED", "SATISFIED"] } } },
    },
    {
      if: {
        properties: {
          record_coherence: { const: "COHERENT" },
          registry_status: { enum: ["REVOKED", "SUSPENDED"] },
        },
      },
      then: {
        properties: { registry_active_condition: { enum: ["NOT_REQUESTED", "NOT_SATISFIED"] } },
      },
    },
    {
      if: {
        properties: {
          record_coherence: { const: "COHERENT" },
          registry_status: { const: "UNKNOWN" },
        },
      },
      then: {
        properties: { registry_active_condition: { enum: ["NOT_REQUESTED", "INDETERMINATE"] } },
      },
    },
    {
      if: { properties: { record_coherence: { enum: ["CONTRADICTORY", "INDETERMINATE"] } } },
      then: {
        properties: { registry_active_condition: { enum: ["NOT_REQUESTED", "INDETERMINATE"] } },
      },
    },
  ];
  report.allOf = allOf;
  report.x_check_count = CHECK_IDS.length;
  report.x_max_reasons = MAX_REPORT_REASONS;
  report.x_max_limitations = MAX_REPORT_LIMITATIONS;
}

/**
 * Produce the exact JSON Schema advertised for a canonical contract. The
 * result is fresh on every call so an MCP server or test cannot mutate the
 * shared schema used by another adapter.
 */
export function createCanonicalJsonSchema(schema: z.ZodType): JsonSchemaDocument {
  const document = z.toJSONSchema(schema, {
    target: "draft-2020-12",
    reused: "ref",
    unrepresentable: "any",
  }) as JsonSchemaDocument;
  // Keep the canonical definitions referenced from `$ref`, while explicitly
  // advertising the wire root as an object.  Draft 2020-12 permits siblings
  // next to `$ref`; some MCP 2025 consumers inspect only the root `type` when
  // deciding whether structured output is an object and otherwise wrap the
  // result in `{ result: ... }`.
  document.type = "object";
  addDateTimeFormats(document);
  if (document.$defs?.[CHECK_SCHEMA_NAME]) addCheckStaticConstraints(document);
  if (document.$defs?.[REPORT_SCHEMA_NAME]) addReportStaticConstraints(document);
  return document;
}

export function getVerifyProofAssetInputJsonSchema(): JsonSchemaDocument {
  return createCanonicalJsonSchema(VerifyProofAssetInputSchema);
}

export function getPublicRecordCheckJsonSchema(): JsonSchemaDocument {
  return createCanonicalJsonSchema(CheckSchema);
}

export function getPublicRecordCoherenceReportJsonSchema(): JsonSchemaDocument {
  return createCanonicalJsonSchema(PublicRecordCoherenceReportSchema);
}

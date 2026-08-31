import { z } from "zod";

import {
  LIMITATION_CODES,
  CHECK_IDS,
  MAX_REPORT_BYTES,
  MAX_REPORT_CHECKS,
  MAX_REPORT_LIMITATIONS,
  MAX_REPORT_REASONS,
  RECORD_COHERENCE_VALUES,
  REGISTRY_ACTIVE_CONDITION_VALUES,
  REGISTRY_STATUS_VALUES,
  REPORT_CONTRACT_ID,
  REPORT_SCHEMA_VERSION,
} from "./constants.js";
import { CheckSchema, ReasonCodeSchema } from "./check.js";
import {
  AssetIdSchema,
  RFC3339DateTimeInputSchema,
  VerifyProofAssetInputSchema,
  type VerifyProofAssetInput,
} from "./input.js";

export const RecordCoherenceSchema = z.enum(RECORD_COHERENCE_VALUES);
export const RegistryStatusSchema = z.enum(REGISTRY_STATUS_VALUES);
export const RegistryActiveConditionSchema = z.enum(REGISTRY_ACTIVE_CONDITION_VALUES);
export const LimitationCodeSchema = z.enum(LIMITATION_CODES);

/**
 * The report is intentionally a normalized conclusion/check document. It has
 * no remote prose, raw receipt, digest, commitment, policy CID, circuit ID,
 * status URL, key ID, or arbitrary evidence field. Those values remain inside
 * the provider/core seam and cannot become CLI/MCP output by accident.
 */
export const PublicRecordCoherenceReportSchema = z
  .strictObject({
    schema_version: z.literal(REPORT_SCHEMA_VERSION),
    contract_id: z.literal(REPORT_CONTRACT_ID),
    asset_id: AssetIdSchema,
    evaluated_at: RFC3339DateTimeInputSchema,
    record_coherence: RecordCoherenceSchema,
    registry_status: RegistryStatusSchema,
    registry_active_condition: RegistryActiveConditionSchema,
    acceptance_decision: z.literal("NOT_PERFORMED"),
    underlying_proof_verification: z.literal("NOT_PERFORMED"),
    predicate_assurance: z.literal("PAR_REPORTED_ONLY"),
    checks: z.array(CheckSchema).length(CHECK_IDS.length).max(MAX_REPORT_CHECKS),
    warnings: z.array(ReasonCodeSchema).max(MAX_REPORT_REASONS),
    errors: z.array(ReasonCodeSchema).max(MAX_REPORT_REASONS),
    limitations: z
      .array(LimitationCodeSchema)
      .length(LIMITATION_CODES.length)
      .max(MAX_REPORT_LIMITATIONS),
  })
  .superRefine((report, context) => {
    const ids = new Set<string>();
    let requiredFail = false;
    let requiredUnknown = false;
    let requiredNonBoundary = 0;
    for (const [index, check] of report.checks.entries()) {
      if (check.id !== CHECK_IDS[index]) {
        context.addIssue({
          code: "custom",
          path: ["checks", index, "id"],
          message: `checks must use canonical order; expected ${CHECK_IDS[index]}`,
        });
      }
      if (ids.has(check.id)) {
        context.addIssue({
          code: "custom",
          path: ["checks", index, "id"],
          message: "check ids must be unique within a report",
        });
      }
      ids.add(check.id);

      if (check.required && check.state === "FAIL") requiredFail = true;
      if (check.required && (check.state === "UNKNOWN" || check.state === "NOT_ASSESSED")) {
        requiredUnknown = true;
      }

      const boundary =
        check.id === "acceptance_decision" ||
        check.id === "underlying_proof_verification" ||
        check.id === "predicate_assurance";
      if (!boundary && check.required) requiredNonBoundary += 1;
      if (boundary) {
        const expectedReason =
          check.id === "acceptance_decision"
            ? "ACCEPTANCE_NOT_PERFORMED"
            : check.id === "underlying_proof_verification"
              ? "PROOF_VERIFICATION_NOT_PERFORMED"
              : "PREDICATE_REPORTED_ONLY";
        if (
          check.state !== "NOT_ASSESSED" ||
          check.reason_code !== expectedReason ||
          check.verification_method !== "NOT_PERFORMED" ||
          check.authority !== "NONE" ||
          check.required
        ) {
          context.addIssue({
            code: "custom",
            path: ["checks", index],
            message:
              "claim-boundary checks must be NOT_ASSESSED, NOT_PERFORMED, NONE, and optional",
          });
        }
      }
    }

    if (requiredNonBoundary === 0) {
      context.addIssue({
        code: "custom",
        path: ["checks"],
        message: "a report requires at least one required non-boundary check",
      });
    }

    for (const requiredId of CHECK_IDS) {
      if (!ids.has(requiredId)) {
        context.addIssue({
          code: "custom",
          path: ["checks"],
          message: `missing required canonical check: ${requiredId}`,
        });
      }
    }
    for (const checkId of ids) {
      if (!(CHECK_IDS as readonly string[]).includes(checkId)) {
        context.addIssue({
          code: "custom",
          path: ["checks"],
          message: `unknown canonical check: ${checkId}`,
        });
      }
    }

    for (const [field, values] of [
      ["warnings", report.warnings],
      ["errors", report.errors],
      ["limitations", report.limitations],
    ] as const) {
      if (new Set(values).size !== values.length) {
        context.addIssue({
          code: "custom",
          path: [field],
          message: `${field} codes must be unique`,
        });
      }
    }

    for (const [index, limitation] of report.limitations.entries()) {
      if (limitation !== LIMITATION_CODES[index]) {
        context.addIssue({
          code: "custom",
          path: ["limitations", index],
          message: `limitations must use the canonical order; expected ${LIMITATION_CODES[index]}`,
        });
      }
    }

    if (report.record_coherence === "COHERENT" && (requiredFail || requiredUnknown)) {
      context.addIssue({
        code: "custom",
        path: ["record_coherence"],
        message: "COHERENT requires every required check to pass",
      });
    }
    if (report.record_coherence === "CONTRADICTORY" && !requiredFail) {
      context.addIssue({
        code: "custom",
        path: ["record_coherence"],
        message: "CONTRADICTORY requires a required failed check",
      });
    }
    if (report.record_coherence === "INDETERMINATE" && (requiredFail || !requiredUnknown)) {
      context.addIssue({
        code: "custom",
        path: ["record_coherence"],
        message:
          "INDETERMINATE requires no required failure and at least one required unknown check",
      });
    }

    if (report.registry_active_condition !== "NOT_REQUESTED") {
      const expectedActiveCondition =
        report.record_coherence !== "COHERENT"
          ? "INDETERMINATE"
          : report.registry_status === "ACTIVE"
            ? "SATISFIED"
            : report.registry_status === "REVOKED" || report.registry_status === "SUSPENDED"
              ? "NOT_SATISFIED"
              : "INDETERMINATE";
      if (report.registry_active_condition !== expectedActiveCondition) {
        context.addIssue({
          code: "custom",
          path: ["registry_active_condition"],
          message: `active condition must be ${expectedActiveCondition} for the report coherence and registry status`,
        });
      }
    }

    let encoded: string;
    try {
      encoded = JSON.stringify(report);
    } catch {
      context.addIssue({
        code: "custom",
        path: [],
        message: "canonical report must be JSON serializable",
      });
      return;
    }
    if (new TextEncoder().encode(encoded).byteLength > MAX_REPORT_BYTES) {
      context.addIssue({
        code: "custom",
        path: [],
        message: "canonical report exceeds its bounded output size",
      });
    }
  })
  .meta({
    id: REPORT_CONTRACT_ID,
    title: "MyProof PAR public-record coherence report",
    description:
      "Evidence-scoped coherence result. It does not independently verify the underlying proof or predicate.",
    x_schema_version: REPORT_SCHEMA_VERSION,
    x_max_bytes: MAX_REPORT_BYTES,
  });

export type PublicRecordCoherenceReport = z.infer<typeof PublicRecordCoherenceReportSchema>;

/** Useful for adapters that need a type-level assertion after parsing. */
export function parsePublicRecordCoherenceReport(value: unknown): PublicRecordCoherenceReport {
  return PublicRecordCoherenceReportSchema.parse(value);
}

/**
 * Parse and bind one canonical report to one caller request. Both adapters
 * use this helper so an asset mismatch or active-condition intent mismatch
 * cannot be handled differently by CLI and MCP.
 */
export function parsePublicRecordCoherenceReportForInput(
  value: unknown,
  input: VerifyProofAssetInput,
): PublicRecordCoherenceReport {
  const parsedInput = VerifyProofAssetInputSchema.parse(input);
  const report = PublicRecordCoherenceReportSchema.parse(value);
  if (report.asset_id !== parsedInput.asset_id) {
    throw new Error("canonical report asset_id does not match the request");
  }
  if (!parsedInput.require_active && report.registry_active_condition !== "NOT_REQUESTED") {
    throw new Error(
      "canonical report active condition must be NOT_REQUESTED when active status is not required",
    );
  }
  if (parsedInput.require_active && report.registry_active_condition === "NOT_REQUESTED") {
    throw new Error("canonical report active condition is missing for an active-status request");
  }
  return report;
}

/**
 * Serialize only a parsed canonical report. This is the typed facade boundary
 * shared by both CLI and MCP, and enforces the same byte budget at the final
 * wire step even if a caller bypasses the Zod parser through a cast.
 */
export function serializePublicRecordCoherenceReport(value: PublicRecordCoherenceReport): string {
  const report = parsePublicRecordCoherenceReport(value);
  const encoded = JSON.stringify(report);
  assertPublicRecordReportBytes(encoded);
  return encoded;
}

/** Apply the same byte budget to an already-serialized CLI/MCP envelope. */
export function assertPublicRecordReportBytes(encoded: string): void {
  if (new TextEncoder().encode(encoded).byteLength > MAX_REPORT_BYTES) {
    throw new RangeError("canonical report exceeds its bounded output size");
  }
}

import { CliInvariantError } from "./errors.js";
import type { CanonicalReport } from "./types.js";
import {
  parsePublicRecordCoherenceReport,
  serializePublicRecordCoherenceReport,
} from "../contracts/index.js";

const MAX_DISPLAY_FIELD = 180;

function displayField(value: unknown, fallback = "unknown"): string {
  if (typeof value !== "string" || value.length === 0) return fallback;
  // The core schema supplies controlled labels. Keep the adapter defensive in
  // case a future producer adds arbitrary remote text.
  let cleaned = "";
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    const isControl =
      codePoint <= 0x1f || codePoint === 0x7f || codePoint === 0x2028 || codePoint === 0x2029;
    cleaned += isControl ? " " : character;
  }
  return cleaned.slice(0, MAX_DISPLAY_FIELD);
}

function checkLabel(check: CanonicalReport["checks"][number], index: number): string {
  return displayField(check.id, `check-${index + 1}`);
}

function checkStatus(check: CanonicalReport["checks"][number]): string {
  return displayField(check.state, "NOT_REPORTED");
}

function checkReason(check: CanonicalReport["checks"][number]): string {
  return displayField(check.reason_code, "MISSING_REASON_CODE");
}

function checkMethod(check: CanonicalReport["checks"][number]): string {
  return displayField(check.verification_method, "MISSING_METHOD");
}

function checkAuthority(check: CanonicalReport["checks"][number]): string {
  return displayField(check.authority, "MISSING_AUTHORITY");
}

function codeList(values: readonly string[]): string {
  return values.length === 0 ? "none" : values.map((value) => displayField(value)).join(", ");
}

/**
 * Human output intentionally contains only canonical summary/check metadata;
 * it does not dump upstream payloads or arbitrary detail fields.
 */
export function formatHumanReport(report: CanonicalReport, assetId: string): string {
  let canonical: CanonicalReport;
  try {
    canonical = parsePublicRecordCoherenceReport(report);
  } catch {
    throw new CliInvariantError();
  }
  if (canonical.asset_id !== assetId) throw new CliInvariantError();

  const lines = [
    "MyProof PAR public-record verification",
    `Asset ID: ${displayField(canonical.asset_id)}`,
    `Contract: ${displayField(canonical.contract_id)}`,
    `Schema version: ${displayField(String(canonical.schema_version))}`,
    `Evaluated at: ${displayField(canonical.evaluated_at)}`,
    `Record coherence: ${displayField(canonical.record_coherence)}`,
    `Registry status: ${displayField(canonical.registry_status)}`,
    `Active requirement: ${displayField(canonical.registry_active_condition)}`,
    `Acceptance decision: ${displayField(canonical.acceptance_decision)}`,
    `Underlying proof verification: ${displayField(canonical.underlying_proof_verification)}`,
    `Predicate assurance: ${displayField(canonical.predicate_assurance)}`,
    `Warnings: ${codeList(canonical.warnings)}`,
    `Errors: ${codeList(canonical.errors)}`,
    `Limitations: ${codeList(canonical.limitations)}`,
    "",
    "Checks:",
  ];

  canonical.checks.forEach((check, index) => {
    lines.push(
      `- ${checkLabel(check, index)}: ${checkStatus(check)} ` +
        `(reason=${checkReason(check)}; method=${checkMethod(check)}; authority=${checkAuthority(check)})`,
    );
  });

  lines.push(
    "",
    "This report checks coherence among published PAR evidence only.",
    "The underlying proof and predicate were not independently verified.",
    "No merchant acceptance decision was performed.",
  );

  return `${lines.join("\n")}\n`;
}

export function formatJsonReport(report: CanonicalReport): string {
  try {
    return `${serializePublicRecordCoherenceReport(report)}\n`;
  } catch {
    throw new CliInvariantError();
  }
}

export function formatSafeError(
  error: { safeCode: string; safeMessage: string },
  json: boolean,
): string {
  if (json) {
    return `${JSON.stringify({ error: { code: error.safeCode, message: error.safeMessage } })}\n`;
  }
  return `myproof-par: ${error.safeMessage} [${error.safeCode}]\n`;
}

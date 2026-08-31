/**
 * Public contract surface for the executable verifier.
 *
 * Provider evidence schemas are intentionally internal. They validate raw
 * PAR/JWS/JWK transport material and are not part of the supported consumer
 * API or its semantic-versioning commitment.
 */
export { AssetIdSchema, parseVerifyProofAssetInput, VerifyProofAssetInputSchema } from "./input.js";
export type { VerifyProofAssetInput } from "./input.js";

export {
  CheckAuthoritySchema,
  CheckIdSchema,
  CheckSchema,
  CheckStateSchema,
  ReasonCodeSchema,
  VerificationMethodSchema,
} from "./check.js";
export type {
  Check,
  CheckAuthority,
  CheckId,
  CheckState,
  ReasonCode,
  VerificationMethod,
} from "./check.js";

export {
  assertPublicRecordReportBytes,
  LimitationCodeSchema,
  PublicRecordCoherenceReportSchema,
  RecordCoherenceSchema,
  RegistryActiveConditionSchema,
  RegistryStatusSchema,
  parsePublicRecordCoherenceReport,
  parsePublicRecordCoherenceReportForInput,
  serializePublicRecordCoherenceReport,
} from "./report.js";
export type { PublicRecordCoherenceReport } from "./report.js";

export type { VerifyProofAssetOptions, VerifyProofAssetRecord } from "./facade.js";

/** Stable vocabulary used by the public report and its check items. */
export {
  CHECK_AUTHORITY_VALUES,
  CHECK_IDS,
  CHECK_STATE_VALUES,
  LIMITATION_CODES,
  REASON_CODES,
  RECORD_COHERENCE_VALUES,
  REGISTRY_ACTIVE_CONDITION_VALUES,
  REGISTRY_STATUS_VALUES,
  REPORT_CONTRACT_ID,
  REPORT_SCHEMA_VERSION,
  VERIFICATION_METHOD_VALUES,
} from "./constants.js";

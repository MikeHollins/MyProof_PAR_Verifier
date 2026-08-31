/** Canonical pure-core facade. Adapters import this module, never a duplicate report producer. */
export { unavailableReport, verifyEvidence, verifyPublicRecord } from "./verify-contract.js";
export type { CoreEvidenceEnvelope, CoreTrustMaterial } from "./evidence.js";

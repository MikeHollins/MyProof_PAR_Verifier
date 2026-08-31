import type { PublicRecordEvidenceInput, VerifyProofAssetInput } from "../contracts/input.js";

/**
 * The one provider-to-core envelope.  This is intentionally an alias to the
 * shared strict contract: a second flattened/compatibility shape would let an
 * adapter silently drop producer fields (notably statusCheck and provenance)
 * before verification.
 */
export type CoreEvidenceEnvelope = PublicRecordEvidenceInput;

export interface CoreTrustMaterial {
  /** Loaded from the package-owned release trust manifest, never the request. */
  readonly manifest: unknown;
  /** Compiled/pinned release digest; mandatory to prevent self-hashed trust. */
  readonly expected_manifest_digest: string;
}

export interface CoreVerificationRequest {
  readonly request: VerifyProofAssetInput;
  readonly evidence: CoreEvidenceEnvelope;
  readonly trust: CoreTrustMaterial;
  readonly now_ms: number;
}

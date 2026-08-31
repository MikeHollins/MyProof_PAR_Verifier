import { createHash, generateKeyPairSync, sign as signBytes, type KeyObject } from "node:crypto";
import { gzipSync } from "node:zlib";
import { encodeBase64Url } from "../../../src/crypto/base64url.js";
import type { JsonWebKeyLike } from "../../../src/crypto/jws.js";
import { computeManifestDigest, type ReleaseTrustManifest } from "../../../src/crypto/trust.js";
import type { CoreEvidenceEnvelope, CoreTrustMaterial } from "../../../src/core/evidence.js";
import type { VerifyProofAssetInput } from "../../../src/contracts/index.js";
import type {
  PublicAssetRecordInput,
  PublicVerificationBundleInput,
  ReceiptJwkInput,
  ReceiptJwksInput,
  StatusCheckInput,
} from "../../../src/contracts/input.js";

/**
 * Independently generated test oracle: Node's built-in ECDSA signer creates
 * the compact JWS values; the production verifier uses the independent
 * `crypto.verify` path. No literal/fake signature is used in a golden case.
 */
export const FIXTURE_ASSET_ID = "00000000-0000-4000-8000-000000000001" as const;
export const FIXTURE_NOW_MS = 1_733_616_000_000; // 2024-12-08T00:00:00.000Z
export const FIXTURE_NOW_SECONDS = Math.floor(FIXTURE_NOW_MS / 1000);

export interface SignedFixture {
  readonly request: VerifyProofAssetInput;
  readonly evidence: CoreEvidenceEnvelope;
  readonly trust: CoreTrustMaterial;
  readonly publicJwk: ReceiptJwkInput;
  readonly privateKey: KeyObject;
  readonly receiptClaims: Record<string, unknown>;
  readonly statusPayload: Record<string, unknown>;
  readonly receiptJws: string;
  readonly statusJws: string;
}

export interface RotatedSignedFixtures {
  readonly old: SignedFixture;
  readonly current: SignedFixture;
  readonly trust: CoreTrustMaterial;
  readonly liveJwks: ReceiptJwksInput;
  readonly oldEvidence: CoreEvidenceEnvelope;
  readonly currentEvidence: CoreEvidenceEnvelope;
}

function compactJws(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: KeyObject,
): string {
  const encodedHeader = encodeBase64Url(Buffer.from(JSON.stringify(header), "utf8"));
  const encodedPayload = encodeBase64Url(Buffer.from(JSON.stringify(payload), "utf8"));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = signBytes("sha256", Buffer.from(signingInput, "ascii"), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${encodeBase64Url(signature)}`;
}

function statusList(index: number, bit: 0 | 1): string {
  const bytes = Buffer.alloc(16 * 1024);
  if (bit === 1) bytes[Math.floor(index / 8)] = 1 << (7 - (index % 8));
  return `u${encodeBase64Url(gzipSync(bytes))}`;
}

function publicJwk(privatePublicKey: KeyObject, kid: string): ReceiptJwkInput {
  const exported = privatePublicKey.export({ format: "jwk" });
  if (typeof exported.x !== "string" || typeof exported.y !== "string") {
    throw new Error("fixture public key is missing P-256 coordinates");
  }
  return {
    kty: "EC",
    crv: "P-256",
    x: exported.x,
    y: exported.y,
    kid,
    alg: "ES256",
    use: "sig",
    key_ops: ["verify"],
    ext: true,
  };
}

export interface SignedFixtureOptions {
  /** Optional deterministic label for key-rotation vectors. */
  readonly kid?: string;
  readonly requireActive?: boolean;
  readonly statusBit?: 0 | 1;
  readonly statusPurpose?: "revocation" | "suspension";
  readonly statusIndex?: string;
  readonly includeConstraintHash?: boolean;
  readonly includeProvenance?: boolean;
  readonly includeCircuitVersion?: boolean;
}

export function createSignedFixture(options: SignedFixtureOptions = {}): SignedFixture {
  const kid = options.kid ?? "fixture-independent-es256-2024";
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = publicJwk(publicKey, kid);
  const statusPurpose = options.statusPurpose ?? "revocation";
  const statusIndex = options.statusIndex ?? "9";
  const statusBitValue = options.statusBit ?? 0;
  const includeCircuitVersion = options.includeCircuitVersion ?? true;
  const statusListUrl = `https://par.myproof.ai/status/${statusPurpose}/default`;
  const proofDigest = "sha256:" + "a".repeat(64);
  const policyHash = "sha256:" + "b".repeat(64);
  const constraintHash = "sha256:" + "c".repeat(64);
  const policyCid = "bafybeifixturepolicycid";
  const circuitId = "myproof/circuit-v1";
  const proofAssetCommitment = "sha256:" + "d".repeat(64);
  const expiresAt = "2024-12-15T00:00:00Z";

  const receiptClaims: Record<string, unknown> = {
    iss: "did:web:par.myproof.ai",
    aud: "myproof-proof-asset",
    sub: FIXTURE_ASSET_ID,
    jti: "fixture-receipt-0001",
    iat: FIXTURE_NOW_SECONDS - 86_400,
    nbf: FIXTURE_NOW_SECONDS - 86_400,
    exp: FIXTURE_NOW_SECONDS + 86_400,
    proof_digest: proofDigest,
    policy_hash: policyHash,
    constraint_hash: constraintHash,
    status_ref: { statusListUrl, statusListIndex: statusIndex, statusPurpose },
    proof_asset_commitment: proofAssetCommitment,
    policy_cid: policyCid,
    circuit_or_schema_id: circuitId,
    ...(includeCircuitVersion ? { circuit_version: 1 } : {}),
    ...(options.includeProvenance ? { environment: "production", configuration_revision: 7 } : {}),
    ...(options.includeProvenance
      ? { policy_ttl_seconds: 1_209_600, proof_expires_at: expiresAt, freshness_source: "policy" }
      : {}),
  };
  const receiptJws = compactJws({ alg: "ES256", typ: "JWT", kid }, receiptClaims, privateKey);

  const validFrom = "2024-12-01T00:00:00Z";
  const validUntil = "2024-12-15T00:00:00Z";
  const statusPayload: Record<string, unknown> = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: statusListUrl,
    type: ["VerifiableCredential", "BitstringStatusListCredential"],
    issuer: "did:web:par.myproof.ai",
    validFrom,
    validUntil,
    credentialSubject: {
      id: `${statusListUrl}#list`,
      type: "BitstringStatusList",
      statusPurpose,
      encodedList: statusList(Number(statusIndex), statusBitValue),
    },
  };
  const statusJws = compactJws(
    { alg: "ES256", typ: "vc+jwt", cty: "vc", kid },
    statusPayload,
    privateKey,
  );

  const asset = {
    proofAssetId: FIXTURE_ASSET_ID,
    proofAssetCommitment,
    proofFormat: "groth16",
    proofDigestPrefix: proofDigest.slice(0, 24),
    digestAlg: "SHA-256",
    constraintCid: "bafkreifixtureconstraintcid",
    ...(options.includeConstraintHash ? { constraintHash } : {}),
    policyHash,
    policyCid,
    circuitOrSchemaId: circuitId,
    circuitCid: "bafkreificircuitcid",
    schemaCid: "bafkreifischemacid",
    verificationStatus: "verified",
    verificationAlgorithm: "groth16",
    verificationTimestamp: "2024-12-01T00:00:00Z",
    verificationMetadata: {
      circuit_version: 1,
      predicate_result: { is_over_21: true },
      proof_digest_prefix: proofDigest.slice(0, 24),
      proof_format: "groth16",
      digest_alg: "SHA-256",
    },
    ...(options.includeProvenance ? { ttlSeconds: 1_209_600 } : {}),
    ...(options.includeProvenance ? { expiresAt } : {}),
    statusListUrl,
    statusListIndex: statusIndex,
    statusPurpose,
    status: {
      purpose: statusPurpose,
      verificationStatus:
        statusBitValue === 0 ? "active" : statusPurpose === "revocation" ? "revoked" : "suspended",
    },
    ...(options.includeProvenance
      ? { _freshness: { ageSeconds: 60, isAdvisoryExpired: false } }
      : {}),
  } satisfies PublicAssetRecordInput;
  const statusCheck = {
    checkedAt: "2024-12-08T00:00:01Z",
    statusListUrl,
    statusListIndex: statusIndex,
    purpose: statusPurpose,
    state:
      statusBitValue === 0 ? "active" : statusPurpose === "revocation" ? "revoked" : "suspended",
  } satisfies StatusCheckInput;
  const provenance: PublicVerificationBundleInput["provenance"] = options.includeProvenance
    ? { environment: "production", configurationRevision: 7, binding: "asset_receipt" }
    : { environment: null, configurationRevision: null, binding: "legacy_unavailable" };
  const checks = {
    receiptSignature: "verified",
    assetBinding: "verified",
    audienceBinding: "verified",
    status:
      statusBitValue === 0 ? "active" : statusPurpose === "revocation" ? "revoked" : "suspended",
    auditAnchor: "omitted",
    auditInclusion: "omitted",
    epochSignature: "omitted",
    authorizedMintRecord: "unavailable",
    assuranceBinding: "unavailable",
  } as const;
  const receiptClaimsProjection: Record<string, unknown> = {
    proof_digest: proofDigest,
    policy_hash: policyHash,
    constraint_hash: constraintHash,
    status_ref: { statusListUrl, statusListIndex: statusIndex, statusPurpose },
    aud: "myproof-proof-asset",
    exp: FIXTURE_NOW_SECONDS + 86_400,
    nbf: FIXTURE_NOW_SECONDS - 86_400,
    iat: FIXTURE_NOW_SECONDS - 86_400,
    iss: "did:web:par.myproof.ai",
    sub: FIXTURE_ASSET_ID,
    proof_asset_commitment: proofAssetCommitment,
    policy_cid: policyCid,
    circuit_or_schema_id: circuitId,
    ...(includeCircuitVersion ? { circuit_version: 1 } : {}),
  };
  const bundle = {
    ok: true,
    schemaVersion: "myproof.public-verification-bundle.v1",
    generatedAt: "2024-12-08T00:00:00Z",
    asset,
    receipt: {
      type: "asset",
      jws: receiptJws,
      header: { alg: "ES256", kid, typ: "JWT" },
      publicJwk: jwk,
      // `jti` intentionally remains only in the signed JWS payload. PAR omits
      // it from the public projection to avoid exposing replay identity.
      claims: receiptClaimsProjection,
    },
    statusCheck,
    provenance,
    // The producer's additive audit=omit representation is accepted by the
    // transport contract but intentionally never reaches a v1 assurance.
    audit: null,
    assurance: null,
    checks,
  } satisfies PublicVerificationBundleInput;
  const manifestUnsigned: Omit<ReleaseTrustManifest, "manifest_digest" | "authenticated"> = {
    schema_version: "myproof.par.release-trust-manifest.v1",
    canonical_origin: "https://par.myproof.ai",
    receipt_issuer: "did:web:par.myproof.ai",
    receipt_keys: [jwk as unknown as JsonWebKeyLike],
    key_retention: {
      receipt_validity_horizon_seconds: 31_536_000,
      rollback_horizon_seconds: 31_536_000,
      historical_keys_required: true,
    },
  };
  const manifest: ReleaseTrustManifest = {
    ...manifestUnsigned,
    manifest_digest: computeManifestDigest(manifestUnsigned),
    authenticated: true,
  };
  return {
    request: { asset_id: FIXTURE_ASSET_ID, require_active: options.requireActive ?? false },
    evidence: {
      bundle,
      receipt_jwks: { keys: [jwk] },
      status_credential: { credential: statusJws, content_type: "application/vc+jwt" },
      status_url: statusListUrl,
    },
    trust: { manifest, expected_manifest_digest: manifest.manifest_digest },
    publicJwk: jwk,
    privateKey,
    receiptClaims,
    statusPayload,
    receiptJws,
    statusJws,
  };
}

/**
 * Build a real two-key release/live overlap. Both receipts and credentials are
 * independently signed; the old protected kid remains usable only while the
 * release and live rings retain the same public key.
 */
export function createRotatedSignedFixtures(): RotatedSignedFixtures {
  const old = createSignedFixture({
    kid: "fixture-rotation-old-2024",
    requireActive: true,
    includeConstraintHash: true,
    includeProvenance: true,
  });
  const current = createSignedFixture({
    kid: "fixture-rotation-current-2025",
    requireActive: true,
    includeConstraintHash: true,
    includeProvenance: true,
  });
  const oldManifest = old.trust.manifest as ReleaseTrustManifest;
  const unsigned: Omit<ReleaseTrustManifest, "manifest_digest" | "authenticated"> = {
    schema_version: oldManifest.schema_version,
    canonical_origin: oldManifest.canonical_origin,
    receipt_issuer: oldManifest.receipt_issuer,
    receipt_keys: [
      old.publicJwk as unknown as JsonWebKeyLike,
      current.publicJwk as unknown as JsonWebKeyLike,
    ],
    key_retention: oldManifest.key_retention,
  };
  const manifest: ReleaseTrustManifest = {
    ...unsigned,
    manifest_digest: computeManifestDigest(unsigned),
    authenticated: true,
  };
  const liveJwks: ReceiptJwksInput = {
    // Put the newer key first to prove selection is by protected kid, not list
    // position. The old key remains present during the rollback horizon.
    keys: [current.publicJwk, old.publicJwk],
  };
  const oldEvidence = structuredClone(old.evidence);
  oldEvidence.receipt_jwks = liveJwks;
  const currentEvidence = structuredClone(current.evidence);
  currentEvidence.receipt_jwks = liveJwks;
  return {
    old,
    current,
    trust: { manifest, expected_manifest_digest: manifest.manifest_digest },
    liveJwks,
    oldEvidence,
    currentEvidence,
  };
}

/** Generate a second valid public key for projection/intersection mutation tests. */
export function createIndependentPublicJwk(kid: string): ReceiptJwkInput {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return publicJwk(publicKey, kid);
}

export function resignReceipt(fixture: SignedFixture, claims: Record<string, unknown>): string {
  return compactJws(
    { alg: "ES256", typ: "JWT", kid: fixture.publicJwk.kid },
    claims,
    fixture.privateKey,
  );
}

export function resignStatus(fixture: SignedFixture, payload: Record<string, unknown>): string {
  return compactJws(
    { alg: "ES256", typ: "vc+jwt", cty: "vc", kid: fixture.publicJwk.kid },
    payload,
    fixture.privateKey,
  );
}

export function alteredPublicKey(fixture: SignedFixture): ReceiptJwkInput {
  const digest = createHash("sha256")
    .update(fixture.publicJwk.x ?? "", "utf8")
    .digest();
  return { ...fixture.publicJwk, x: encodeBase64Url(digest.subarray(0, 32)) };
}

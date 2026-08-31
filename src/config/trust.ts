import packageManifestJson from "../../configs/release-trust-manifest.json" with { type: "json" };
import type { CoreTrustMaterial } from "../core/evidence.js";
import {
  TRUST_MANIFEST_SCHEMA,
  validateReleaseTrustManifest,
  type ReleaseTrustManifest,
} from "../crypto/trust.js";

/**
 * This value is deliberately a separately compiled release input, not a
 * digest derived from the JSON loaded below. A release build must replace it
 * together with the package-owned manifest after PAR's key owner authorizes
 * the exact public key ring. The checked-in placeholder is fail-closed.
 */
export const RELEASE_TRUST_MANIFEST_DIGEST_PIN =
  "bb2f6db506741d6ca8818bec9a025650578ffc6d49ba7ac14c7caefd7b4d7620" as const;

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const child of Object.values(value as object)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/**
 * Load only the package-owned release artifact. There is intentionally no
 * path, URL, environment, or caller argument here. `authenticated:true` is
 * created only for the in-package validation candidate; it is never accepted
 * as an authority supplied by remote evidence.
 */
export function loadPackageTrustMaterial(): CoreTrustMaterial {
  const raw = isObject(packageManifestJson) ? structuredClone(packageManifestJson) : {};
  const candidate = { ...raw, authenticated: true };
  const validated = validateReleaseTrustManifest(candidate, RELEASE_TRUST_MANIFEST_DIGEST_PIN);
  if (validated.ok) {
    return deepFreeze({
      manifest: validated.manifest,
      expected_manifest_digest: RELEASE_TRUST_MANIFEST_DIGEST_PIN,
    });
  }

  // Keep an invalid/unconfigured release visibly invalid. Never silently turn
  // a malformed or unpinned artifact into a trust root.
  const failClosedManifest: Record<string, unknown> = {
    schema_version: TRUST_MANIFEST_SCHEMA,
    canonical_origin: "https://par.myproof.ai",
    receipt_issuer: "did:web:par.myproof.ai",
    receipt_keys: [],
    manifest_digest: "",
    authenticated: false,
  };
  return deepFreeze({
    manifest: failClosedManifest,
    expected_manifest_digest: RELEASE_TRUST_MANIFEST_DIGEST_PIN,
  });
}

/** Default production trust is package-owned and fail-closed until a release pin is authorized. */
export const defaultTrustMaterial: CoreTrustMaterial = loadPackageTrustMaterial();

/** Type-only helper for release tooling and tests; runtime callers use the loader above. */
export type PackageReleaseTrustManifest = ReleaseTrustManifest;

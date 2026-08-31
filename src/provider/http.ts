/**
 * The network boundary for the public PAR verifier.
 *
 * This module deliberately knows nothing about proof semantics.  It only
 * fetches the three public documents needed by the verification core and
 * makes the network contract small enough to audit:
 *
 *   - one immutable HTTPS origin;
 *   - a finite set of path shapes;
 *   - GET only, no credentials and no caller-selected URLs;
 *   - no redirects;
 *   - bounded, content-type checked response bodies;
 *   - timeout and caller-abort propagation; and
 *   - bounded concurrent requests.
 *
 * Do not add a generic `fetch(url)` escape hatch here.  A future public PAR
 * document must get an explicit path builder and a response validator.
 */

import {
  AssetIdSchema,
  PublicRecordEvidenceInputSchema,
  PublicVerificationBundleInputSchema,
  ReceiptJwksInputSchema,
  StatusReferenceInputSchema,
} from "../contracts/input.js";
import type {
  PublicRecordEvidenceInput,
  PublicVerificationBundleInput,
  ReceiptJwksInput,
  StatusReferenceInput,
} from "../contracts/input.js";
import {
  CANONICAL_PAR_ORIGIN,
  CANONICAL_RECEIPT_JWKS_PATH,
  MAX_EVIDENCE_BYTES,
  MAX_STATUS_CREDENTIAL_BYTES,
  VERIFICATION_BUNDLE_PATH_TEMPLATE,
} from "../contracts/constants.js";
import { decodeBase64Url } from "../crypto/base64url.js";

export { CANONICAL_PAR_ORIGIN };

const CANONICAL_ORIGIN_URL = new URL(`${CANONICAL_PAR_ORIGIN}/`);
const STATUS_LIST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const COMPACT_JWS_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
const P256_COORDINATE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const DEFAULT_TIMEOUT_MS = 8_000;
const DEFAULT_MAX_CONCURRENCY = 3;
const DEFAULT_MAX_BUNDLE_BYTES = MAX_EVIDENCE_BYTES;
const DEFAULT_MAX_JWKS_BYTES = 131_072;
// The signed VC carries a base64url-encoded gzip status list.  The core caps
// the expanded list at 16 MiB; 24 MiB bounds the encoded credential while
// leaving room for the JOSE envelope without accepting an unbounded stream.
const DEFAULT_MAX_STATUS_BYTES = MAX_STATUS_CREDENTIAL_BYTES;
const MAX_JWKS_KEYS = 32;
const MAX_JSON_DEPTH = 32;
const MAX_JSON_KEYS = 512;
const MAX_JSON_STRING_BYTES = 262_144;
const MAX_COMPACT_JWS_BYTES = 24 * 1024 * 1024;
const MAX_HEADER_VALUE_BYTES = 8_192;

/** The only status-list purposes currently understood by the public API. */
export type StatusPurpose = StatusReferenceInput["statusPurpose"];

export type StatusReference = StatusReferenceInput;

/**
 * The shared contract owns the PAR bundle and JWKS shapes.  The provider
 * performs bounded transport validation before returning these values, while
 * the core remains responsible for cryptographic and semantic checks.
 */
export type VerificationBundleDocument = PublicVerificationBundleInput;

export type ReceiptJwksDocument = ReceiptJwksInput;

/** The one lossless provider-to-core envelope owned by the shared contract. */
export type PublicRecordEvidence = PublicRecordEvidenceInput;

interface FetchResponseLike {
  readonly status: number;
  readonly url?: string;
  readonly redirected?: boolean;
  readonly headers: {
    get(name: string): string | null;
  };
  readonly body?: unknown;
  arrayBuffer(): Promise<ArrayBuffer>;
}

type FetchLike = (
  input: string | URL,
  init?: {
    method?: string;
    headers?: Record<string, string>;
    credentials?: "omit";
    redirect?: "error";
    signal?: AbortSignal;
  },
) => Promise<FetchResponseLike>;

export interface ParProviderLimits {
  timeoutMs?: number;
  maxConcurrency?: number;
  maxBundleBytes?: number;
  maxJwksBytes?: number;
  maxStatusBytes?: number;
}

export type ProviderResource = "bundle" | "receipt-jwks" | "status";

export type ProviderErrorCode =
  | "INVALID_ASSET_ID"
  | "INVALID_STATUS_REFERENCE"
  | "UNSAFE_URL"
  | "FETCH_FAILED"
  | "ABORTED"
  | "TIMEOUT"
  | "REDIRECT_REJECTED"
  | "HTTP_STATUS"
  | "CONTENT_TYPE_MISMATCH"
  | "CONTENT_ENCODING_UNSUPPORTED"
  | "CONTENT_LENGTH_INVALID"
  | "BODY_TOO_LARGE"
  | "INVALID_TEXT"
  | "INVALID_JSON"
  | "INVALID_RESPONSE";

/**
 * Errors are intentionally safe to print.  They contain no URL, asset ID,
 * response body, token, key material, or upstream exception text.
 */
export class ParProviderError extends Error {
  override readonly name = "ParProviderError";

  constructor(
    readonly code: ProviderErrorCode,
    readonly resource: ProviderResource | "input",
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }

  toJSON(): Record<string, unknown> {
    return {
      code: this.code,
      resource: this.resource,
      ...(this.status === undefined ? {} : { status: this.status }),
    };
  }
}

interface NormalizedLimits {
  timeoutMs: number;
  maxConcurrency: number;
  maxBundleBytes: number;
  maxJwksBytes: number;
  maxStatusBytes: number;
}

interface QueueWaiter {
  resolve: () => void;
  reject: (error: unknown) => void;
  signal: AbortSignal | undefined;
  onAbort: (() => void) | undefined;
}

/** A FIFO semaphore with cancellation while queued. */
class Semaphore {
  private inFlight = 0;
  private readonly waiters: QueueWaiter[] = [];

  constructor(private readonly limit: number) {}

  get active(): number {
    return this.inFlight;
  }

  async acquire(signal?: AbortSignal): Promise<() => void> {
    if (signal?.aborted) {
      throw new ParProviderError("ABORTED", "input", "Provider operation was aborted");
    }

    if (this.inFlight < this.limit) {
      this.inFlight += 1;
      return this.release.bind(this);
    }

    await new Promise<void>((resolve, reject) => {
      const waiter: QueueWaiter = { resolve, reject, signal, onAbort: undefined };
      if (signal?.aborted) {
        reject(new ParProviderError("ABORTED", "input", "Provider operation was aborted"));
        return;
      }
      if (signal) {
        waiter.onAbort = () => {
          const index = this.waiters.indexOf(waiter);
          if (index >= 0) this.waiters.splice(index, 1);
          reject(new ParProviderError("ABORTED", "input", "Provider operation was aborted"));
        };
        signal.addEventListener("abort", waiter.onAbort, { once: true });
      }
      if (signal?.aborted) {
        waiter.onAbort?.();
        return;
      }
      this.waiters.push(waiter);
      // Abort can race the queue insertion.  The second check closes the
      // interval between addEventListener() and push(), where an already
      // fired signal would otherwise strand a queued waiter until a later
      // release.
      if (signal?.aborted) waiter.onAbort?.();
    });

    if (signal?.aborted) {
      // release() was already reserved for this waiter by the producer.  If
      // the signal flipped between wake-up and this continuation, hand that
      // slot on rather than leaking it.
      this.release();
      throw new ParProviderError("ABORTED", "input", "Provider operation was aborted");
    }
    // release() transfers the already-counted slot to this waiter.  Do not
    // increment here: doing so creates a window where a new caller can claim
    // the same slot before this continuation resumes.
    return this.release.bind(this);
  }

  private release(): void {
    if (this.inFlight <= 0) return;
    for (;;) {
      const waiter = this.waiters.shift();
      if (!waiter) {
        this.inFlight -= 1;
        return;
      }
      if (waiter.onAbort && waiter.signal) {
        waiter.signal.removeEventListener("abort", waiter.onAbort);
      }
      // A queued request may have been aborted after it was removed from the
      // queue but before its continuation ran.  Skip it and transfer the same
      // slot to the next waiter rather than stranding capacity.
      if (waiter.signal?.aborted) {
        waiter.reject(new ParProviderError("ABORTED", "input", "Provider operation was aborted"));
        continue;
      }
      // Keep inFlight unchanged: the slot is transferred atomically to the
      // waiter.  Its acquire() continuation returns the corresponding lease.
      waiter.resolve();
      return;
    }
  }
}

interface RequestSpec {
  resource: ProviderResource;
  url: URL;
  accept: string;
  contentType: "json" | "application/vc+jwt";
  maxBytes: number;
  signal: AbortSignal | undefined;
}

/**
 * Fixed-origin, read-only public PAR provider.
 *
 * The constructor intentionally has no `origin` or fetch-adapter argument.
 * Tests replace the platform fetch in their isolated harness; production
 * callers cannot redirect verification to another host or response source.
 */
export class ParPublicProvider {
  private readonly limits: NormalizedLimits;
  private readonly semaphore: Semaphore;

  constructor(options: ParProviderLimits = {}) {
    this.limits = normalizeLimits(options);
    this.semaphore = new Semaphore(this.limits.maxConcurrency);
  }

  get activeRequests(): number {
    return this.semaphore.active;
  }

  /** Construct the only bundle URL accepted by this provider. */
  buildVerificationBundleUrl(assetId: string): URL {
    assertAssetId(assetId);
    const path = VERIFICATION_BUNDLE_PATH_TEMPLATE.replace("{asset_id}", assetId);
    return buildCanonicalUrl(path, {
      audit: "omit",
    });
  }

  /** Construct the only receipt-key URL accepted by this provider. */
  buildReceiptJwksUrl(): URL {
    return buildCanonicalUrl(CANONICAL_RECEIPT_JWKS_PATH);
  }

  /**
   * Validate and construct a status-list URL from untrusted receipt data.
   * Only the canonical PAR status-list path is accepted; URLs from any other
   * host, scheme, port, query, fragment, user-info, or path are rejected.
   */
  buildStatusUrl(reference: StatusReference): URL {
    const parsed = parseStatusReference(reference);
    const path = `/status/${parsed.statusPurpose}/${parsed.listId}`;
    const expected = buildCanonicalUrl(path);
    if (parsed.url !== expected.href) {
      throw new ParProviderError(
        "INVALID_STATUS_REFERENCE",
        "status",
        "PAR status reference is not a canonical status-list path",
      );
    }
    return expected;
  }

  async fetchVerificationBundle(
    assetId: string,
    signal?: AbortSignal,
  ): Promise<VerificationBundleDocument> {
    const url = this.buildVerificationBundleUrl(assetId);
    const document = await this.requestJson({
      resource: "bundle",
      url,
      accept: "application/json",
      contentType: "json",
      maxBytes: this.limits.maxBundleBytes,
      signal,
    });
    return validateVerificationBundle(document);
  }

  async fetchReceiptJwks(signal?: AbortSignal): Promise<ReceiptJwksDocument> {
    const document = await this.requestJson({
      resource: "receipt-jwks",
      url: this.buildReceiptJwksUrl(),
      accept: "application/json",
      contentType: "json",
      maxBytes: this.limits.maxJwksBytes,
      signal,
    });
    return validateReceiptJwks(document);
  }

  async fetchStatusCredential(
    reference: StatusReference,
    signal?: AbortSignal,
  ): Promise<{ url: string; credential: string; contentType: "application/vc+jwt" }> {
    const url = this.buildStatusUrl(reference);
    const body = await this.requestText({
      resource: "status",
      url,
      // This is intentionally not application/json.  A JSON status response
      // is advisory and cannot satisfy the signed status evidence contract.
      accept: "application/vc+jwt",
      contentType: "application/vc+jwt",
      maxBytes: this.limits.maxStatusBytes,
      signal,
    });
    validateCompactJws(body, "status");
    return { url: url.href, credential: body, contentType: "application/vc+jwt" };
  }

  /**
   * Fetch all public evidence needed by the pure core as the one shared
   * envelope. Bundle and JWKS are fetched concurrently under the provider
   * semaphore; status is fetched only after its URL has been validated from
   * the returned bundle.
   */
  async fetchPublicRecordEvidence(
    assetId: string,
    signal?: AbortSignal,
  ): Promise<PublicRecordEvidence> {
    // Validate before starting any network work, including the parallel key
    // request.  This also keeps invalid identifiers out of diagnostics.
    assertAssetId(assetId);
    const operationController = new AbortController();
    let parentAbort: (() => void) | undefined;
    if (signal) {
      if (signal.aborted) {
        operationController.abort(signal.reason);
      } else {
        parentAbort = () => operationController.abort(signal.reason);
        signal.addEventListener("abort", parentAbort, { once: true });
      }
    }
    try {
      const [bundle, receiptJwks] = await Promise.all([
        this.fetchVerificationBundle(assetId, operationController.signal),
        this.fetchReceiptJwks(operationController.signal),
      ]).catch((error: unknown) => {
        // Do not leave the sibling request running after one document has
        // failed.  This matters for finite concurrency and for callers that
        // retry after an indeterminate provider result.
        operationController.abort(error);
        throw error;
      });
      const statusReference = extractStatusReference(bundle);
      const status = await this.fetchStatusCredential(statusReference, operationController.signal);
      return validatePublicRecordEvidence({
        // Keep the producer's exact shared bundle intact.  In particular, do
        // not reconstruct or drop schemaVersion, statusCheck, provenance,
        // assurance, checks, audit=null, freshness, or producer metadata.
        bundle,
        receipt_jwks: receiptJwks,
        status_credential: {
          credential: status.credential,
          content_type: status.contentType,
        },
        // This is the exact canonical URL passed to fetch, never caller input.
        status_url: status.url,
      });
    } finally {
      operationController.abort();
      if (parentAbort && signal) signal.removeEventListener("abort", parentAbort);
    }
  }

  private async requestJson(spec: RequestSpec): Promise<Record<string, unknown>> {
    const text = await this.requestText(spec);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new ParProviderError("INVALID_JSON", spec.resource, "PAR returned invalid JSON");
    }
    assertSafeJson(parsed, spec.resource);
    if (!isRecord(parsed)) {
      throw new ParProviderError(
        "INVALID_RESPONSE",
        spec.resource,
        "PAR returned a JSON value where an object was required",
      );
    }
    return parsed;
  }

  private async requestText(spec: RequestSpec): Promise<string> {
    const release = await this.semaphore.acquire(spec.signal);
    try {
      return await this.performRequest(spec);
    } finally {
      release();
    }
  }

  private async performRequest(spec: RequestSpec): Promise<string> {
    const controller = new AbortController();
    let timedOut = false;
    let onAbort: (() => void) | undefined;

    if (spec.signal) {
      if (spec.signal.aborted) {
        throw new ParProviderError("ABORTED", spec.resource, "Provider operation was aborted");
      }
      onAbort = () => controller.abort(spec.signal?.reason);
      spec.signal.addEventListener("abort", onAbort, { once: true });
    }
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.limits.timeoutMs);

    try {
      const response = await abortableOperation(
        Promise.resolve().then(() =>
          defaultFetch(spec.url, {
            method: "GET",
            headers: {
              Accept: spec.accept,
              // Avoid implicit content negotiation that could change the wire
              // contract across fetch implementations or proxies.
              "Accept-Encoding": "identity",
            },
            // A verifier may be embedded in a browser page hosted on the
            // canonical origin. Never let ambient cookies or HTTP auth cross
            // this read-only boundary.
            credentials: "omit",
            redirect: "error",
            signal: controller.signal,
          }),
        ),
        controller.signal,
        () => {
          if (timedOut) {
            throw new ParProviderError("TIMEOUT", spec.resource, "PAR request timed out");
          }
          if (spec.signal?.aborted) {
            throw new ParProviderError("ABORTED", spec.resource, "Provider operation was aborted");
          }
          throw new ParProviderError("ABORTED", spec.resource, "Provider operation was aborted");
        },
      );

      // Validate the response shape and final URL before status classification
      // so malformed adapters and redirects fail closed regardless of status.
      validateResponseMetadata(response, spec);
      if (response.status < 200 || response.status > 299) {
        throw new ParProviderError(
          "HTTP_STATUS",
          spec.resource,
          "PAR returned an unsuccessful HTTP status",
          response.status,
        );
      }
      // Error responses commonly carry HTML or a different encoding. Once
      // shape and URL are trusted, status is the deterministic primary result;
      // content negotiation applies only to successful responses.
      validateContentHeaders(response, spec);
      // Keep the timeout and parent abort listener alive while consuming the
      // body.  A response whose headers arrive promptly can still be a slow
      // or unbounded stream.
      return await readBoundedBody(response, spec, controller.signal, () => {
        if (timedOut) {
          throw new ParProviderError("TIMEOUT", spec.resource, "PAR request timed out");
        }
        if (spec.signal?.aborted) {
          throw new ParProviderError("ABORTED", spec.resource, "Provider operation was aborted");
        }
      });
    } catch (error) {
      if (error instanceof ParProviderError) throw error;
      if (timedOut) {
        throw new ParProviderError("TIMEOUT", spec.resource, "PAR request timed out");
      }
      if (spec.signal?.aborted || controller.signal.aborted) {
        throw new ParProviderError("ABORTED", spec.resource, "Provider operation was aborted");
      }
      throw new ParProviderError("FETCH_FAILED", spec.resource, "PAR request failed");
    } finally {
      if (timer) clearTimeout(timer);
      if (onAbort && spec.signal) spec.signal.removeEventListener("abort", onAbort);
    }
  }
}

export function createParPublicProvider(options: ParProviderLimits = {}): ParPublicProvider {
  return new ParPublicProvider(options);
}

export function assertAssetId(assetId: unknown): asserts assetId is string {
  if (!AssetIdSchema.safeParse(assetId).success) {
    throw new ParProviderError(
      "INVALID_ASSET_ID",
      "input",
      "Asset ID must be a canonical lowercase UUID",
    );
  }
}

function normalizeLimits(options: ParProviderLimits): NormalizedLimits {
  return {
    timeoutMs: positiveInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS, "timeoutMs", 120_000),
    maxConcurrency: positiveInteger(
      options.maxConcurrency,
      DEFAULT_MAX_CONCURRENCY,
      "maxConcurrency",
      16,
    ),
    maxBundleBytes: positiveInteger(
      options.maxBundleBytes,
      DEFAULT_MAX_BUNDLE_BYTES,
      "maxBundleBytes",
      16 * 1024 * 1024,
    ),
    maxJwksBytes: positiveInteger(
      options.maxJwksBytes,
      DEFAULT_MAX_JWKS_BYTES,
      "maxJwksBytes",
      4 * 1024 * 1024,
    ),
    maxStatusBytes: positiveInteger(
      options.maxStatusBytes,
      DEFAULT_MAX_STATUS_BYTES,
      "maxStatusBytes",
      32 * 1024 * 1024,
    ),
  };
}

function positiveInteger(
  value: number | undefined,
  fallback: number,
  name: string,
  max: number,
): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value <= 0 || value > max) {
    throw new RangeError(`${name} must be a positive integer no greater than ${max}`);
  }
  return value;
}

function buildCanonicalUrl(pathname: string, query?: Record<string, string>): URL {
  // Pathnames are constants or assembled only from validated, delimiter-free
  // identifiers.  Still verify the result so future edits cannot accidentally
  // loosen the origin invariant.
  const url = new URL(pathname, CANONICAL_PAR_ORIGIN);
  if (
    url.origin !== CANONICAL_ORIGIN_URL.origin ||
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port !== ""
  ) {
    throw new ParProviderError("UNSAFE_URL", "input", "Provider constructed an unsafe URL");
  }
  // The path builders own query construction. Never silently normalize a
  // future path constant that already contains a query or fragment.
  if (url.search !== "" || url.hash !== "") {
    throw new ParProviderError("UNSAFE_URL", "input", "Provider constructed an unsafe URL");
  }
  if (query) {
    const entries = Object.entries(query);
    for (const [key, value] of entries) url.searchParams.set(key, value);
  }
  return url;
}

function parseStatusReference(reference: unknown): {
  url: string;
  statusPurpose: StatusPurpose;
  listId: string;
  statusListIndex: string;
} {
  const parsedReference = StatusReferenceInputSchema.safeParse(reference);
  if (!parsedReference.success) {
    throw new ParProviderError(
      "INVALID_STATUS_REFERENCE",
      "status",
      "PAR status reference is invalid",
    );
  }
  const { statusListUrl, statusPurpose } = parsedReference.data;

  let url: URL;
  try {
    url = new URL(statusListUrl);
  } catch {
    throw new ParProviderError(
      "INVALID_STATUS_REFERENCE",
      "status",
      "PAR status reference is invalid",
    );
  }
  if (
    url.origin !== CANONICAL_ORIGIN_URL.origin ||
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.port !== "" ||
    url.search !== "" ||
    url.hash !== ""
  ) {
    throw new ParProviderError(
      "INVALID_STATUS_REFERENCE",
      "status",
      "PAR status reference is not canonical",
    );
  }
  // PAR's frozen public receipt wire uses `/status/{purpose}/default`.
  // Keep the allowlist finite: do not turn this into a generic status URL
  // fetcher merely because a receipt contains a URL-shaped value.
  const match = /^\/status\/(revocation|suspension)\/(default)$/.exec(url.pathname);
  const matchedPurpose = match?.[1];
  const matchedListId = match?.[2];
  if (
    !matchedPurpose ||
    !matchedListId ||
    matchedPurpose !== statusPurpose ||
    !STATUS_LIST_ID_PATTERN.test(matchedListId)
  ) {
    throw new ParProviderError(
      "INVALID_STATUS_REFERENCE",
      "status",
      "PAR status path is not allowlisted",
    );
  }
  const canonicalHref = `${CANONICAL_PAR_ORIGIN}/status/${matchedPurpose}/${matchedListId}`;
  if (statusListUrl !== canonicalHref || url.href !== canonicalHref) {
    throw new ParProviderError(
      "INVALID_STATUS_REFERENCE",
      "status",
      "PAR status URL is not the exact canonical URL",
    );
  }
  // The index is not used for URL construction, but validating it at this
  // seam prevents a malformed status reference from reaching the core.
  return {
    url: url.href,
    statusPurpose,
    listId: matchedListId,
    statusListIndex: parsedReference.data.statusListIndex,
  };
}

function validateResponseUrl(response: FetchResponseLike, spec: RequestSpec): void {
  // Native fetch always supplies a boolean. Treat an absent/hostile value as
  // unsafe rather than allowing a custom platform adapter to hide a redirect.
  if (response.redirected !== false) {
    throw new ParProviderError(
      "REDIRECT_REJECTED",
      spec.resource,
      "PAR redirects are not accepted",
    );
  }
  if (typeof response.url !== "string" || response.url !== spec.url.href) {
    throw new ParProviderError(
      "REDIRECT_REJECTED",
      spec.resource,
      "PAR response URL changed unexpectedly",
    );
  }
}

function validateContentHeaders(response: FetchResponseLike, spec: RequestSpec): void {
  if (!response.headers || typeof response.headers.get !== "function") {
    throw new ParProviderError(
      "INVALID_RESPONSE",
      spec.resource,
      "PAR response headers are invalid",
    );
  }
  const contentType = mediaType(readHeader(response, spec, "content-type"));
  const expected = spec.contentType === "json" ? "application/json" : "application/vc+jwt";
  if (contentType !== expected) {
    throw new ParProviderError(
      "CONTENT_TYPE_MISMATCH",
      spec.resource,
      "PAR returned an unexpected content type",
    );
  }

  const encoding = readHeader(response, spec, "content-encoding");
  if (encoding !== null && encoding.trim().toLowerCase() !== "identity") {
    // We request identity and reject compressed responses at the boundary.
    // This avoids relying on a platform's automatic decompressor and makes
    // the byte limit a real decompressed-body limit rather than a proxy hint.
    throw new ParProviderError(
      "CONTENT_ENCODING_UNSUPPORTED",
      spec.resource,
      "Compressed PAR responses are not accepted",
    );
  }

  const contentLength = readHeader(response, spec, "content-length");
  if (contentLength !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(contentLength)) {
      throw new ParProviderError(
        "CONTENT_LENGTH_INVALID",
        spec.resource,
        "PAR response content length is invalid",
      );
    }
    const parsed = Number(contentLength);
    if (!Number.isSafeInteger(parsed)) {
      throw new ParProviderError(
        "CONTENT_LENGTH_INVALID",
        spec.resource,
        "PAR response content length is invalid",
      );
    }
    if (parsed > spec.maxBytes) {
      throw new ParProviderError(
        "BODY_TOO_LARGE",
        spec.resource,
        "PAR response exceeds the configured byte limit",
      );
    }
  }
}

function readHeader(response: FetchResponseLike, spec: RequestSpec, name: string): string | null {
  let value: unknown;
  try {
    value = response.headers.get(name);
  } catch {
    throw new ParProviderError(
      "INVALID_RESPONSE",
      spec.resource,
      "PAR response headers are invalid",
    );
  }
  if (value !== null && typeof value !== "string") {
    throw new ParProviderError(
      "INVALID_RESPONSE",
      spec.resource,
      "PAR response headers are invalid",
    );
  }
  if (value !== null && new TextEncoder().encode(value).byteLength > MAX_HEADER_VALUE_BYTES) {
    throw new ParProviderError(
      "INVALID_RESPONSE",
      spec.resource,
      "PAR response headers are invalid",
    );
  }
  return value;
}

function mediaType(value: string | null): string {
  if (!value) return "";
  return (value.split(";", 1)[0] ?? "").trim().toLowerCase();
}

function validateResponseShape(response: FetchResponseLike, spec: RequestSpec): void {
  // A native Response has all of these fields. Keep platform responses
  // fail-closed as well: malformed adapters must not bypass URL, header, or
  // body bounds by throwing an incidental TypeError later in the pipeline.
  if (response === null || typeof response !== "object") {
    throw new ParProviderError("INVALID_RESPONSE", spec.resource, "PAR response is invalid");
  }
  if (!Number.isSafeInteger(response.status) || response.status < 100 || response.status > 599) {
    throw new ParProviderError("INVALID_RESPONSE", spec.resource, "PAR response status is invalid");
  }
  if (response.headers === null || typeof response.headers !== "object") {
    throw new ParProviderError(
      "INVALID_RESPONSE",
      spec.resource,
      "PAR response headers are invalid",
    );
  }
  if (typeof response.arrayBuffer !== "function" && !isReadableBody(response.body)) {
    throw new ParProviderError("INVALID_RESPONSE", spec.resource, "PAR response body is invalid");
  }
}

function validateResponseMetadata(response: FetchResponseLike, spec: RequestSpec): void {
  try {
    validateResponseShape(response, spec);
    validateResponseUrl(response, spec);
  } catch (error) {
    if (error instanceof ParProviderError) throw error;
    throw new ParProviderError(
      "INVALID_RESPONSE",
      spec.resource,
      "PAR response metadata is invalid",
    );
  }
}

async function readBoundedBody(
  response: FetchResponseLike,
  spec: RequestSpec,
  signal: AbortSignal,
  checkAbort: () => void,
): Promise<string> {
  if (signal.aborted) checkAbort();
  const body = response.body;
  let bytes: Uint8Array;
  if (isReadableBody(body)) {
    bytes = await readStreamBounded(body, spec, signal, checkAbort);
  } else {
    let buffer: ArrayBuffer;
    try {
      buffer = await abortableOperation(response.arrayBuffer(), signal, checkAbort);
    } catch (error) {
      if (error instanceof ParProviderError) throw error;
      throw new ParProviderError(
        "FETCH_FAILED",
        spec.resource,
        "PAR response body could not be read",
      );
    }
    bytes = new Uint8Array(buffer);
    if (bytes.byteLength > spec.maxBytes) {
      throw new ParProviderError(
        "BODY_TOO_LARGE",
        spec.resource,
        "PAR response exceeds the configured byte limit",
      );
    }
  }

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new ParProviderError("INVALID_TEXT", spec.resource, "PAR response was not valid UTF-8");
  }
}

interface Reader<T> {
  read(): Promise<{ done: boolean; value?: T }>;
  cancel?(reason?: unknown): Promise<void>;
  releaseLock?(): void;
}

interface ReadableBody {
  getReader(): Reader<Uint8Array>;
}

function isReadableBody(value: unknown): value is ReadableBody {
  return isRecord(value) && typeof value.getReader === "function";
}

async function readStreamBounded(
  body: ReadableBody,
  spec: RequestSpec,
  signal: AbortSignal,
  checkAbort: () => void,
): Promise<Uint8Array> {
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      let result: { done: boolean; value?: Uint8Array };
      try {
        result = await abortableOperation(reader.read(), signal, checkAbort);
      } catch (error) {
        // Preserve deterministic timeout/abort errors from checkAbort.  The
        // generic body-read error is only used for a hostile reader failure.
        checkAbort();
        if (error instanceof ParProviderError) throw error;
        throw new ParProviderError(
          "FETCH_FAILED",
          spec.resource,
          "PAR response body could not be read",
        );
      }
      checkAbort();
      if (result === null || typeof result !== "object" || typeof result.done !== "boolean") {
        throw new ParProviderError(
          "INVALID_RESPONSE",
          spec.resource,
          "PAR response body metadata was invalid",
        );
      }
      if (result.done) break;
      const chunk = result.value;
      if (!(chunk instanceof Uint8Array)) {
        throw new ParProviderError("INVALID_TEXT", spec.resource, "PAR response body was invalid");
      }
      total += chunk.byteLength;
      if (total > spec.maxBytes) {
        try {
          const cancellation = reader.cancel?.("response too large");
          // Do not let a hostile body keep cancellation pending forever.  The
          // deterministic size error below is already the terminal outcome.
          if (cancellation) void cancellation.catch(() => undefined);
        } catch {
          // The size violation is the useful deterministic error.
        }
        throw new ParProviderError(
          "BODY_TOO_LARGE",
          spec.resource,
          "PAR response exceeds the configured byte limit",
        );
      }
      chunks.push(chunk);
    }
  } finally {
    if (signal.aborted) {
      // Abort the reader too. Fetch's signal should cancel the network body,
      // but a platform reader can otherwise retain a pending read after the
      // bounded operation has already returned its error.
      try {
        const cancellation = reader.cancel?.("provider operation aborted");
        if (cancellation) void Promise.resolve(cancellation).catch(() => undefined);
      } catch {
        // Preserve the original timeout/abort/body error.
      }
    }
    // Do not leave a reader locked if a hostile body rejects or exceeds its
    // limit. `releaseLock` is optional on the platform body implementation.
    try {
      reader.releaseLock?.();
    } catch {
      // Preserve the original body/abort/size error if a hostile reader also
      // refuses to release its lock.
    }
  }

  checkAbort();
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

/**
 * Race a potentially stalled platform/body operation with the request's
 * deadline.  The underlying promise still receives a rejection handler so a
 * late hostile response cannot become an unhandled rejection.
 */
async function abortableOperation<T>(
  operation: Promise<T>,
  signal: AbortSignal | undefined,
  checkAbort: () => void,
): Promise<T> {
  if (signal?.aborted) checkAbort();
  if (!signal) return operation;
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      callback();
    };
    const onAbort = () => {
      finish(() => {
        try {
          checkAbort();
          reject(new Error("operation aborted"));
        } catch (error) {
          reject(error);
        }
      });
    };
    signal.addEventListener("abort", onAbort, { once: true });
    operation.then(
      (value) => finish(() => resolve(value)),
      (error) => finish(() => reject(error)),
    );
    if (signal.aborted) onAbort();
  });
}

export function validateVerificationBundle(value: unknown): VerificationBundleDocument {
  // Exported validators are also used directly by integration callers, so
  // retain the same bounded JSON/prototype checks as the HTTP path.
  assertSafeJson(value, "bundle");
  const parsed = PublicVerificationBundleInputSchema.safeParse(value);
  if (!parsed.success) {
    throw new ParProviderError(
      "INVALID_RESPONSE",
      "bundle",
      "PAR verification bundle shape is invalid",
    );
  }
  const bundle = parsed.data;
  if (bundle.ok !== true || bundle.schemaVersion !== "myproof.public-verification-bundle.v1") {
    throw new ParProviderError(
      "INVALID_RESPONSE",
      "bundle",
      "PAR verification bundle schema version is invalid",
    );
  }
  validateCompactJws(bundle.receipt.jws, "bundle");
  return bundle;
}

export function validateReceiptJwks(value: unknown): ReceiptJwksDocument {
  // Keep direct callers on the same hostile-JSON/prototype-pollution guard as
  // the HTTP path. The schema validator is not a replacement for bounded
  // recursive input validation.
  assertSafeJson(value, "receipt-jwks");
  const parsed = ReceiptJwksInputSchema.safeParse(value);
  if (!parsed.success || parsed.data.keys.length === 0 || parsed.data.keys.length > MAX_JWKS_KEYS) {
    throw new ParProviderError(
      "INVALID_RESPONSE",
      "receipt-jwks",
      "PAR receipt JWKS shape is invalid",
    );
  }
  const seenKids = new Set<string>();
  for (const key of parsed.data.keys) {
    if (!KEY_ID_PATTERN.test(key.kid)) {
      throw new ParProviderError(
        "INVALID_RESPONSE",
        "receipt-jwks",
        "PAR receipt JWKS key is invalid",
      );
    }
    if (seenKids.has(key.kid)) {
      throw new ParProviderError(
        "INVALID_RESPONSE",
        "receipt-jwks",
        "PAR receipt JWKS contains duplicate key IDs",
      );
    }
    seenKids.add(key.kid);
    if (key.kty !== "EC" || key.crv !== "P-256" || key.alg !== "ES256") {
      throw new ParProviderError(
        "INVALID_RESPONSE",
        "receipt-jwks",
        "PAR receipt JWKS algorithm is invalid",
      );
    }
    if (!isCanonicalP256Coordinate(key.x) || !isCanonicalP256Coordinate(key.y)) {
      throw new ParProviderError(
        "INVALID_RESPONSE",
        "receipt-jwks",
        "PAR receipt JWKS coordinates are invalid",
      );
    }
    if (key.use !== undefined && key.use !== "sig") {
      throw new ParProviderError(
        "INVALID_RESPONSE",
        "receipt-jwks",
        "PAR receipt JWKS use is invalid",
      );
    }
    if (key.key_ops !== undefined && (key.key_ops.length === 0 || key.key_ops.length > 4)) {
      throw new ParProviderError(
        "INVALID_RESPONSE",
        "receipt-jwks",
        "PAR receipt JWKS operations are invalid",
      );
    }
  }
  return parsed.data;
}

/**
 * Validate the one provider-to-core envelope before it leaves this boundary.
 * This is deliberately the shared schema, not a provider-local flattened
 * compatibility shape.
 */
export function validatePublicRecordEvidence(value: unknown): PublicRecordEvidence {
  // The status credential is a bounded compact JWS that can be larger than
  // the generic JSON response string cap because it may carry a compressed
  // status list. The nested shared schema still enforces its exact maximum.
  assertSafeJson(value, "bundle", 0, MAX_STATUS_CREDENTIAL_BYTES);
  const parsed = PublicRecordEvidenceInputSchema.safeParse(value);
  if (!parsed.success) {
    throw new ParProviderError(
      "INVALID_RESPONSE",
      "bundle",
      "PAR public-record evidence envelope is invalid",
    );
  }
  return parsed.data;
}

function isCanonicalP256Coordinate(value: string): boolean {
  if (!P256_COORDINATE_PATTERN.test(value)) return false;
  try {
    return decodeBase64Url(value, "jwk_coordinate").byteLength === 32;
  } catch {
    return false;
  }
}

export function extractStatusReference(bundle: VerificationBundleDocument): StatusReference {
  const statusRef = bundle.receipt.claims.status_ref;
  if (!isRecord(statusRef)) {
    throw new ParProviderError(
      "INVALID_STATUS_REFERENCE",
      "status",
      "PAR receipt status reference is missing",
    );
  }
  // parseStatusReference performs all strict shape/path checks.  Return only
  // the whitelisted fields and never pass the rest of the remote object on.
  const parsed = parseStatusReference(statusRef);
  return {
    statusListUrl: parsed.url,
    statusListIndex: parsed.statusListIndex,
    statusPurpose: parsed.statusPurpose,
  };
}

function validateCompactJws(value: string, resource: ProviderResource): void {
  if (value.length < 8 || value.length > MAX_COMPACT_JWS_BYTES || /[^\x21-\x7e]/.test(value)) {
    throw new ParProviderError(
      "INVALID_RESPONSE",
      resource,
      "PAR returned an invalid signed credential",
    );
  }
  const segments = value.split(".");
  if (
    segments.length !== 3 ||
    segments.some((segment) => !COMPACT_JWS_SEGMENT_PATTERN.test(segment))
  ) {
    throw new ParProviderError("INVALID_RESPONSE", resource, "PAR returned an invalid compact JWS");
  }
}

function assertSafeJson(
  value: unknown,
  resource: ProviderResource,
  depth = 0,
  maxStringBytes = MAX_JSON_STRING_BYTES,
): void {
  if (depth > MAX_JSON_DEPTH) {
    throw new ParProviderError("INVALID_RESPONSE", resource, "PAR JSON nesting is too deep");
  }
  if (typeof value === "string") {
    if (new TextEncoder().encode(value).byteLength > maxStringBytes) {
      throw new ParProviderError("INVALID_RESPONSE", resource, "PAR JSON string is too large");
    }
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    if (value.length > MAX_JSON_KEYS) {
      throw new ParProviderError("INVALID_RESPONSE", resource, "PAR JSON array is too large");
    }
    for (const item of value) assertSafeJson(item, resource, depth + 1, maxStringBytes);
    return;
  }
  if (!isRecord(value)) return;
  const entries = Object.entries(value);
  if (entries.length > MAX_JSON_KEYS) {
    throw new ParProviderError("INVALID_RESPONSE", resource, "PAR JSON object has too many fields");
  }
  for (const [key, item] of entries) {
    if (key === "__proto__" || key === "prototype" || key === "constructor") {
      throw new ParProviderError("INVALID_RESPONSE", resource, "PAR JSON contains an unsafe field");
    }
    assertSafeJson(item, resource, depth + 1, maxStringBytes);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function defaultFetch(
  input: string | URL,
  init?: Parameters<FetchLike>[1],
): Promise<FetchResponseLike> {
  const fetchFunction = globalThis.fetch;
  if (typeof fetchFunction !== "function") {
    throw new Error("A Fetch implementation is required");
  }
  return fetchFunction(input, init);
}

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  CANONICAL_PAR_ORIGIN,
  ParProviderError,
  ParPublicProvider,
  extractStatusReference,
  validateReceiptJwks,
  validatePublicRecordEvidence,
  validateVerificationBundle,
  type StatusReference,
} from "../../src/provider/http.js";
import {
  PublicRecordEvidenceInputSchema,
  PublicVerificationBundleInputSchema,
} from "../../src/contracts/input.js";

const ASSET_ID = "550e8400-e29b-41d4-a716-446655440000";
const OTHER_ASSET_ID = "550e8400-e29b-41d4-a716-446655440001";
const PRODUCER_ASSET_ID = "11111111-1111-4111-8111-111111111111";
const BUNDLE_URL = `${CANONICAL_PAR_ORIGIN}/api/public/proof-assets/${ASSET_ID}/verification-bundle?audit=omit`;
const PRODUCER_BUNDLE_URL = `${CANONICAL_PAR_ORIGIN}/api/public/proof-assets/${PRODUCER_ASSET_ID}/verification-bundle?audit=omit`;
const JWKS_URL = `${CANONICAL_PAR_ORIGIN}/api/public/receipts/jwks.json`;
const STATUS_URL = `${CANONICAL_PAR_ORIGIN}/status/revocation/default`;
const PRODUCER_WIRE_SHA256 = "ff7043feb3cf7c646adce0695468d6d2978a402474599198e4335de4e7483404";
const PRODUCER_RAW_SHA256 = "4b765d27c75606c03da3fdd4d47fa2605e1f2117ebb96a97076ca453cb78fa88";
const nativeFetch = globalThis.fetch;

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

// The bundle fixture is copied byte-for-byte from PAR's checked-in
// audit=omit artifact. The separate JWKS and status files remain bounded
// transport fixtures; none of these fixtures claims cryptographic validity or
// a COHERENT result.
const bundleFixture = readJson("producer-omit-wire.json");
const jwksFixture = readJson("structural-receipt-jwks.json");
const statusFixture = readText("structural-status.vc-jwt");

function readText(name: string): string {
  return readFileSync(new URL(`../fixtures/provider/${name}`, import.meta.url), "utf8").trim();
}

function readRawText(name: string): string {
  return readFileSync(new URL(`../fixtures/provider/${name}`, import.meta.url), "utf8");
}

function readBytes(name: string): Buffer {
  return readFileSync(new URL(`../fixtures/provider/${name}`, import.meta.url));
}

function readJson(name: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(readText(name));
  if (!isJsonRecord(parsed)) throw new Error(`fixture ${name} must contain a JSON object`);
  return parsed;
}

function bundleFor(assetId: string): string {
  const copy = structuredClone(bundleFixture);
  recordAt(copy, "asset").proofAssetId = assetId;
  return JSON.stringify(copy);
}

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function recordAt(value: Record<string, unknown>, key: string): Record<string, unknown> {
  const child = value[key];
  if (!isJsonRecord(child)) throw new Error(`fixture field ${key} must be an object`);
  return child;
}

function recordsAt(value: Record<string, unknown>, key: string): Record<string, unknown>[] {
  const child = value[key];
  if (!Array.isArray(child) || !child.every(isJsonRecord)) {
    throw new Error(`fixture field ${key} must be an object array`);
  }
  return child;
}

function firstRecord(records: Record<string, unknown>[], label: string): Record<string, unknown> {
  const first = records[0];
  if (!first) throw new Error(`fixture field ${label} must not be empty`);
  return first;
}

type JsonPathPart = string | number;

function valueAtPath(value: unknown, path: readonly JsonPathPart[]): unknown {
  let current = value;
  for (const part of path) {
    if (Array.isArray(current)) {
      if (typeof part !== "number") throw new Error("array path segment must be numeric");
      current = current[part];
    } else if (isJsonRecord(current)) {
      current = current[String(part)];
    } else {
      throw new Error(`path does not reach an object at ${String(part)}`);
    }
  }
  return current;
}

function objectAtPath(value: unknown, path: readonly JsonPathPart[]): Record<string, unknown> {
  const object = valueAtPath(value, path);
  if (!isJsonRecord(object)) throw new Error(`path does not identify an object: ${path.join(".")}`);
  return object;
}

function addMutationField(value: Record<string, unknown>, path: readonly JsonPathPart[]): void {
  Reflect.set(objectAtPath(value, path), "__provider_mutation", true);
}

function deleteField(value: Record<string, unknown>, path: readonly JsonPathPart[]): void {
  if (path.length === 0) throw new Error("cannot delete the root value");
  const parent = objectAtPath(value, path.slice(0, -1));
  Reflect.deleteProperty(parent, String(path[path.length - 1]));
}

function producerProvider(
  bundle: Record<string, unknown> = bundleFixture,
  jwks: Record<string, unknown> = jwksFixture,
): ParPublicProvider {
  const fetchImpl: FetchLike = async (input) => {
    const url = String(input);
    if (url === PRODUCER_BUNDLE_URL) return responseFor(JSON.stringify(bundle), url);
    if (url === JWKS_URL) return responseFor(JSON.stringify(jwks), url);
    if (url === STATUS_URL) {
      return responseFor(statusFixture, url, { "content-type": "application/vc+jwt" });
    }
    throw new Error("unexpected URL");
  };
  return providerFor(fetchImpl);
}

function producerEnvelope(): Record<string, unknown> {
  return {
    bundle: structuredClone(bundleFixture),
    receipt_jwks: structuredClone(jwksFixture),
    status_credential: {
      credential: statusFixture,
      content_type: "application/vc+jwt",
    },
    status_url: STATUS_URL,
  };
}

function headers(values: Record<string, string> = { "content-type": "application/json" }): {
  get(name: string): string | null;
} {
  const normalized = new Map(
    Object.entries(values).map(([key, value]) => [key.toLowerCase(), value]),
  );
  return {
    get(name: string): string | null {
      return normalized.get(name.toLowerCase()) ?? null;
    },
  };
}

function bytesFor(body: string): Uint8Array {
  return new TextEncoder().encode(body);
}

function arrayBufferFor(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function responseFor(
  body: string,
  url: string,
  values: Record<string, string> = { "content-type": "application/json" },
  options: { status?: number; redirected?: boolean; stream?: boolean } = {},
): FetchResponseLike {
  const bytes = bytesFor(body);
  let consumed = false;
  const reader = {
    read: async (): Promise<{ done: boolean; value?: Uint8Array }> => {
      if (consumed) return { done: true };
      consumed = true;
      return { done: false, value: bytes };
    },
    cancel: async (): Promise<void> => undefined,
    releaseLock: (): void => undefined,
  };
  return {
    status: options.status ?? 200,
    url,
    redirected: options.redirected ?? false,
    headers: headers(values),
    body: options.stream === false ? undefined : { getReader: () => reader },
    arrayBuffer: async () => arrayBufferFor(bytes),
  };
}

function fetchReturning(response: FetchResponseLike): {
  fetchImpl: FetchLike;
  calls: Array<{ input: string | URL; init?: Parameters<FetchLike>[1] }>;
} {
  const calls: Array<{ input: string | URL; init?: Parameters<FetchLike>[1] }> = [];
  const fetchImpl: FetchLike = async (input, init) => {
    calls.push({ input, init });
    return response;
  };
  return { fetchImpl, calls };
}

function providerFor(
  fetchImpl: FetchLike,
  options: ConstructorParameters<typeof ParPublicProvider>[0] = {},
) {
  useFetch(fetchImpl);
  return new ParPublicProvider(options);
}

function useFetch(fetchImpl: FetchLike): void {
  Reflect.set(globalThis, "fetch", fetchImpl);
}

afterEach(() => {
  Reflect.set(globalThis, "fetch", nativeFetch);
});

function expectProviderError(promise: Promise<unknown>, code: string): Promise<void> {
  return expect(promise).rejects.toMatchObject({ code });
}

describe("fixed-origin URL construction", () => {
  it("uses only the canonical bundle path and additive audit=omit mode", () => {
    const provider = new ParPublicProvider();
    expect(provider.buildVerificationBundleUrl(ASSET_ID).href).toBe(BUNDLE_URL);
    expect(provider.buildReceiptJwksUrl().href).toBe(JWKS_URL);
  });

  it("pins the PAR-produced audit=omit fixture bytes and canonical wire hash", () => {
    const raw = readBytes("producer-omit-wire.json");
    expect(createHash("sha256").update(raw).digest("hex")).toBe(PRODUCER_RAW_SHA256);
    const parsed = JSON.parse(raw.toString("utf8")) as unknown;
    const wire = JSON.stringify(parsed);
    expect(createHash("sha256").update(wire, "utf8").digest("hex")).toBe(PRODUCER_WIRE_SHA256);
  });

  it.each([
    "550E8400-E29B-41D4-A716-446655440000",
    "550e8400-e29b-01d4-a716-446655440000",
    "550e8400-e29b-41d4-7116-446655440000",
    "asset/../other",
    "asset%2Fother",
    "550e8400-e29b-41d4-a716-446655440000?x=1",
    "550e8400-e29b-41d4-a716-446655440000#x",
    "550e8400-e29b-41d4-a716-446655440000\\other",
    "550e8400-e29b-41d4-a716-446655440000\n",
    "https://attacker.invalid/asset",
  ])("rejects asset path injection %j before network access", (assetId) => {
    const provider = new ParPublicProvider();
    expect(() => provider.buildVerificationBundleUrl(assetId)).toThrowError(
      expect.objectContaining({ code: "INVALID_ASSET_ID" }),
    );
  });

  it("accepts the frozen canonical PAR status URL only", () => {
    const provider = new ParPublicProvider();
    const reference: StatusReference = {
      statusListUrl: STATUS_URL,
      statusListIndex: "0",
      statusPurpose: "revocation",
    };
    expect(provider.buildStatusUrl(reference).href).toBe(STATUS_URL);
  });

  it.each([
    "https://par.myproof.ai/status/lists/revocation/default",
    "https://attacker.invalid/status/revocation/default",
    "http://par.myproof.ai/status/revocation/default",
    "https://par.myproof.ai/status/revocation/default?redirect=https://attacker.invalid",
    "https://user:pass@par.myproof.ai/status/revocation/default",
    "https://par.myproof.ai:443/status/revocation/default",
    "https://PAR.MYPROOF.AI/status/revocation/default",
    "https://par.myproof.ai/status/revocation/default/",
    "https://par.myproof.ai/status/revocation/default/../other",
    "https://par.myproof.ai/status/revocation/%64efault",
    "https://par.myproof.ai/status/revocation/other",
  ])("rejects unsafe status reference %j", (statusListUrl) => {
    const provider = new ParPublicProvider();
    expect(() =>
      provider.buildStatusUrl({
        statusListUrl,
        statusListIndex: "0",
        statusPurpose: "revocation",
      }),
    ).toThrowError(expect.objectContaining({ code: "INVALID_STATUS_REFERENCE" }));
  });

  it.each([
    { statusListIndex: "-1", statusPurpose: "revocation" },
    { statusListIndex: "01", statusPurpose: "revocation" },
    { statusListIndex: "0", statusPurpose: "other" },
  ])("rejects malformed status metadata %j", (metadata) => {
    const provider = new ParPublicProvider();
    expect(() =>
      Reflect.apply(provider.buildStatusUrl, provider, [
        { statusListUrl: STATUS_URL, ...metadata },
      ]),
    ).toThrowError(expect.objectContaining({ code: "INVALID_STATUS_REFERENCE" }));
  });
});

describe("bounded read-only requests", () => {
  it("sends GET, redirect:error, identity encoding, and the exact content negotiation", async () => {
    const { fetchImpl, calls } = fetchReturning(responseFor(bundleFor(ASSET_ID), BUNDLE_URL));
    const provider = providerFor(fetchImpl);
    await provider.fetchVerificationBundle(ASSET_ID);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.input).toEqual(new URL(BUNDLE_URL));
    expect(calls[0]?.init).toMatchObject({
      method: "GET",
      redirect: "error",
      credentials: "omit",
      headers: { Accept: "application/json", "Accept-Encoding": "identity" },
    });
    expect(calls[0]?.init?.signal).toBeInstanceOf(AbortSignal);
  });

  it("requests signed status credentials as application/vc+jwt", async () => {
    const { fetchImpl, calls } = fetchReturning(
      responseFor(statusFixture, STATUS_URL, { "content-type": "application/vc+jwt" }),
    );
    const provider = providerFor(fetchImpl);
    await provider.fetchStatusCredential({
      statusListUrl: STATUS_URL,
      statusListIndex: "0",
      statusPurpose: "revocation",
    });
    expect(calls[0]?.input).toEqual(new URL(STATUS_URL));
    expect(calls[0]?.init?.headers).toMatchObject({
      Accept: "application/vc+jwt",
      "Accept-Encoding": "identity",
    });
    expect(calls[0]?.init).toMatchObject({ credentials: "omit" });
  });

  it("rejects redirects even when the fetch implementation returns a 200", async () => {
    const { fetchImpl } = fetchReturning(
      responseFor(
        bundleFor(ASSET_ID),
        BUNDLE_URL,
        { "content-type": "application/json" },
        { redirected: true },
      ),
    );
    useFetch(fetchImpl);
    await expectProviderError(
      new ParPublicProvider().fetchVerificationBundle(ASSET_ID),
      "REDIRECT_REJECTED",
    );
  });

  it("classifies status before successful-response content negotiation", async () => {
    await expectProviderError(
      providerFor(
        fetchReturning(responseFor(bundleFor(ASSET_ID), `${CANONICAL_PAR_ORIGIN}/other`)).fetchImpl,
      ).fetchVerificationBundle(ASSET_ID),
      "REDIRECT_REJECTED",
    );
    await expectProviderError(
      providerFor(
        fetchReturning(
          responseFor("not-found", BUNDLE_URL, { "content-type": "text/html" }, { status: 404 }),
        ).fetchImpl,
      ).fetchVerificationBundle(ASSET_ID),
      "HTTP_STATUS",
    );
    await expectProviderError(
      providerFor(
        fetchReturning(
          responseFor(
            "not-found",
            BUNDLE_URL,
            { "content-type": "text/html", "content-encoding": "gzip" },
            { status: 404 },
          ),
        ).fetchImpl,
      ).fetchVerificationBundle(ASSET_ID),
      "HTTP_STATUS",
    );
    await expectProviderError(
      providerFor(
        fetchReturning(
          responseFor(bundleFor(ASSET_ID), BUNDLE_URL, { "content-type": "text/html" }),
        ).fetchImpl,
      ).fetchVerificationBundle(ASSET_ID),
      "CONTENT_TYPE_MISMATCH",
    );
    await expectProviderError(
      providerFor(
        fetchReturning(
          responseFor(bundleFor(ASSET_ID), BUNDLE_URL, {
            "content-type": "application/json",
            "content-encoding": "identity; gzip",
          }),
        ).fetchImpl,
      ).fetchVerificationBundle(ASSET_ID),
      "CONTENT_ENCODING_UNSUPPORTED",
    );
  });

  it("fails closed when a fetch adapter omits response metadata", async () => {
    const missingRedirectFlag = responseFor(bundleFor(ASSET_ID), BUNDLE_URL);
    Reflect.deleteProperty(missingRedirectFlag, "redirected");
    useFetch(fetchReturning(missingRedirectFlag).fetchImpl);
    await expectProviderError(
      new ParPublicProvider().fetchVerificationBundle(ASSET_ID),
      "REDIRECT_REJECTED",
    );

    const invalidStatus = responseFor(bundleFor(ASSET_ID), BUNDLE_URL);
    Reflect.set(invalidStatus, "status", Number.NaN);
    useFetch(fetchReturning(invalidStatus).fetchImpl);
    await expectProviderError(
      new ParPublicProvider().fetchVerificationBundle(ASSET_ID),
      "INVALID_RESPONSE",
    );

    const invalidHeaders = responseFor(bundleFor(ASSET_ID), BUNDLE_URL);
    Reflect.deleteProperty(invalidHeaders, "headers");
    useFetch(fetchReturning(invalidHeaders).fetchImpl);
    await expectProviderError(
      new ParPublicProvider().fetchVerificationBundle(ASSET_ID),
      "INVALID_RESPONSE",
    );

    const throwingHeaders = responseFor(bundleFor(ASSET_ID), BUNDLE_URL);
    Object.defineProperty(throwingHeaders, "headers", {
      value: {
        get: () => {
          throw new Error("header adapter failure");
        },
      },
      configurable: true,
    });
    useFetch(fetchReturning(throwingHeaders).fetchImpl);
    await expectProviderError(
      new ParPublicProvider().fetchVerificationBundle(ASSET_ID),
      "INVALID_RESPONSE",
    );

    const malformedEncodingHeader = responseFor(bundleFor(ASSET_ID), BUNDLE_URL, {
      "content-type": "application/json",
      "content-encoding": "",
    });
    useFetch(fetchReturning(malformedEncodingHeader).fetchImpl);
    await expectProviderError(
      new ParPublicProvider().fetchVerificationBundle(ASSET_ID),
      "CONTENT_ENCODING_UNSUPPORTED",
    );
  });

  it("enforces declared and streamed decompressed byte limits", async () => {
    const declared = responseFor("{}", BUNDLE_URL, {
      "content-type": "application/json",
      "content-length": "100",
    });
    useFetch(fetchReturning(declared).fetchImpl);
    await expectProviderError(
      new ParPublicProvider({ maxBundleBytes: 10 }).fetchVerificationBundle(ASSET_ID),
      "BODY_TOO_LARGE",
    );

    const bytes = bytesFor(bundleFor(ASSET_ID));
    const streamed: FetchResponseLike = {
      status: 200,
      url: BUNDLE_URL,
      redirected: false,
      headers: headers({ "content-type": "application/json" }),
      body: {
        getReader: () => ({
          read: async () => ({ done: false, value: bytes }),
          cancel: async () => undefined,
          releaseLock: () => undefined,
        }),
      },
      arrayBuffer: async () => arrayBufferFor(bytes),
    };
    useFetch(fetchReturning(streamed).fetchImpl);
    await expectProviderError(
      new ParPublicProvider({ maxBundleBytes: 10 }).fetchVerificationBundle(ASSET_ID),
      "BODY_TOO_LARGE",
    );
  });

  it("rejects malformed stream read metadata before parsing", async () => {
    const malformed = responseFor("{}", BUNDLE_URL);
    Reflect.set(malformed, "body", {
      getReader: () => ({
        read: async () => ({ done: "yes" }),
        cancel: async () => undefined,
      }),
    });
    useFetch(fetchReturning(malformed).fetchImpl);
    await expectProviderError(
      new ParPublicProvider().fetchVerificationBundle(ASSET_ID),
      "INVALID_RESPONSE",
    );
  });

  it("rejects invalid UTF-8 and malformed JSON without exposing the body", async () => {
    const invalidUtf8 = new Uint8Array([0xff, 0xfe]);
    const response: FetchResponseLike = {
      status: 200,
      url: BUNDLE_URL,
      redirected: false,
      headers: headers(),
      body: undefined,
      arrayBuffer: async () => invalidUtf8.buffer,
    };
    useFetch(fetchReturning(response).fetchImpl);
    const invalidText = await new ParPublicProvider()
      .fetchVerificationBundle(ASSET_ID)
      .catch((error: unknown) => error);
    expect(invalidText).toMatchObject({ code: "INVALID_TEXT" });
    expect(JSON.stringify(invalidText)).not.toContain("ff");

    const malformed = responseFor('{"ok":', BUNDLE_URL);
    useFetch(fetchReturning(malformed).fetchImpl);
    await expectProviderError(
      new ParPublicProvider().fetchVerificationBundle(ASSET_ID),
      "INVALID_JSON",
    );
  });

  it("fails closed on prototype-pollution fields and unsafe wire shapes", async () => {
    // Use a raw JSON document to exercise the parser's own-field guard.
    const raw = responseFor('{"__proto__":{"polluted":true}}', BUNDLE_URL);
    useFetch(fetchReturning(raw).fetchImpl);
    await expectProviderError(
      new ParPublicProvider().fetchVerificationBundle(ASSET_ID),
      "INVALID_RESPONSE",
    );

    const wrongAsset = structuredClone(bundleFixture);
    recordAt(wrongAsset, "asset").proofAssetId = OTHER_ASSET_ID;
    const preserved = validateVerificationBundle(wrongAsset);
    expect(preserved.asset.proofAssetId).toBe(OTHER_ASSET_ID);
  });
});

describe("response validation seams", () => {
  it("validates receipt JWS shape and key-ring algorithms before the core", () => {
    expect(() => validateVerificationBundle(bundleFixture)).not.toThrow();
    const malformed = structuredClone(bundleFixture);
    recordAt(malformed, "receipt").jws = "not-a-jws";
    expect(() => validateVerificationBundle(malformed)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE" }),
    );

    expect(() => validateReceiptJwks(jwksFixture)).not.toThrow();
    const confusion = structuredClone(jwksFixture);
    firstRecord(recordsAt(confusion, "keys"), "keys").alg = "RS256";
    expect(() => validateReceiptJwks(confusion)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE" }),
    );
    const privateKey = structuredClone(jwksFixture);
    firstRecord(recordsAt(privateKey, "keys"), "keys").d = "private";
    expect(() => validateReceiptJwks(privateKey)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE" }),
    );
    const duplicate = structuredClone(jwksFixture);
    const duplicateKey = firstRecord(recordsAt(duplicate, "keys"), "keys");
    Reflect.set(duplicate, "keys", [duplicateKey, duplicateKey]);
    expect(() => validateReceiptJwks(duplicate)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE" }),
    );
    const operationConfusion = structuredClone(jwksFixture);
    firstRecord(recordsAt(operationConfusion, "keys"), "keys").key_ops = ["verify", "sign"];
    expect(() => validateReceiptJwks(operationConfusion)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE" }),
    );

    const shortCoordinate = structuredClone(jwksFixture);
    firstRecord(recordsAt(shortCoordinate, "keys"), "keys").x = "A".repeat(42);
    expect(() => validateReceiptJwks(shortCoordinate)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE" }),
    );
    const nonCanonicalCoordinate = structuredClone(jwksFixture);
    firstRecord(recordsAt(nonCanonicalCoordinate, "keys"), "keys").y = "A".repeat(44);
    expect(() => validateReceiptJwks(nonCanonicalCoordinate)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE" }),
    );

    const nonCanonicalBase64url = structuredClone(jwksFixture);
    // 43 characters is the right width, but the final base64url quantum has
    // non-zero padding bits and therefore is not a canonical 32-byte value.
    firstRecord(recordsAt(nonCanonicalBase64url, "keys"), "keys").x = `${"A".repeat(42)}B`;
    expect(() => validateReceiptJwks(nonCanonicalBase64url)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE" }),
    );

    const unsafeField = structuredClone(jwksFixture);
    Object.defineProperty(unsafeField, "__proto__", {
      value: { polluted: true },
      enumerable: true,
      configurable: true,
      writable: true,
    });
    expect(() => validateReceiptJwks(unsafeField)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE" }),
    );

    const overBound = structuredClone(jwksFixture);
    Reflect.set(
      overBound,
      "keys",
      Array.from({ length: 33 }, (_, index) => ({
        ...firstRecord(recordsAt(jwksFixture, "keys"), "keys"),
        kid: `receipt-fixture-${index}`,
      })),
    );
    expect(() => validateReceiptJwks(overBound)).toThrowError(
      expect.objectContaining({ code: "INVALID_RESPONSE" }),
    );
  });

  it("extracts only the allowlisted status reference from the receipt", () => {
    const bundle = validateVerificationBundle(bundleFixture);
    const extracted = extractStatusReference(bundle);
    expect(extracted).toEqual({
      statusListUrl: STATUS_URL,
      statusListIndex: "7",
      statusPurpose: "revocation",
    });
  });
});

describe("timeout, cancellation, and bounded concurrency", () => {
  it("times out a fetch implementation that ignores its abort signal", async () => {
    const fetchImpl: FetchLike = async () => new Promise<FetchResponseLike>(() => undefined);
    const started = Date.now();
    useFetch(fetchImpl);
    await expectProviderError(
      new ParPublicProvider({ timeoutMs: 30 }).fetchVerificationBundle(ASSET_ID),
      "TIMEOUT",
    );
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("times out a response whose headers arrive but whose body never yields", async () => {
    const stalled = responseFor("", BUNDLE_URL);
    Reflect.set(stalled, "body", {
      getReader: () => ({
        read: () => new Promise<{ done: boolean }>(() => undefined),
        cancel: async () => undefined,
      }),
    });
    const started = Date.now();
    useFetch(fetchReturning(stalled).fetchImpl);
    await expectProviderError(
      new ParPublicProvider({ timeoutMs: 30 }).fetchVerificationBundle(ASSET_ID),
      "TIMEOUT",
    );
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it("propagates caller cancellation while fetching and while consuming a body", async () => {
    const before = new AbortController();
    before.abort();
    const calls = vi.fn<FetchLike>(async () => responseFor(bundleFor(ASSET_ID), BUNDLE_URL));
    useFetch(calls);
    await expectProviderError(
      new ParPublicProvider().fetchVerificationBundle(ASSET_ID, before.signal),
      "ABORTED",
    );
    expect(calls).not.toHaveBeenCalled();

    const during = new AbortController();
    const fetchImpl: FetchLike = async (_input, init) =>
      new Promise<FetchResponseLike>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
        during.abort();
      });
    useFetch(fetchImpl);
    await expectProviderError(
      new ParPublicProvider().fetchVerificationBundle(ASSET_ID, during.signal),
      "ABORTED",
    );

    const bodyAbort = new AbortController();
    const stalled = responseFor("", BUNDLE_URL);
    Reflect.set(stalled, "body", {
      getReader: () => ({ read: () => new Promise<{ done: boolean }>(() => undefined) }),
    });
    useFetch(fetchReturning(stalled).fetchImpl);
    const request = new ParPublicProvider({ timeoutMs: 5000 }).fetchVerificationBundle(
      ASSET_ID,
      bodyAbort.signal,
    );
    setTimeout(() => bodyAbort.abort(), 10);
    await expectProviderError(request, "ABORTED");
  });

  it("never exceeds maxConcurrency during queued interleavings", async () => {
    const gateResolvers: Array<() => void> = [];
    let active = 0;
    let peak = 0;
    const fetchImpl: FetchLike = async (input) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise<void>((resolve) => gateResolvers.push(resolve));
      active -= 1;
      const url = String(input);
      const matchedAssetId =
        /proof-assets\/([^/]+)\/verification-bundle/.exec(url)?.[1] ?? ASSET_ID;
      return responseFor(bundleFor(matchedAssetId), url);
    };
    useFetch(fetchImpl);
    const provider = new ParPublicProvider({ maxConcurrency: 2, timeoutMs: 5000 });
    const requests = [0, 1, 2, 3, 4].map((index) =>
      provider.fetchVerificationBundle(`550e8400-e29b-41d4-a716-44665544000${index}`),
    );
    for (let i = 0; i < 5; i += 1) {
      await vi.waitFor(() => expect(gateResolvers.length).toBeGreaterThan(0));
      gateResolvers.shift()?.();
    }
    await Promise.all(requests);
    expect(peak).toBeLessThanOrEqual(2);
    expect(provider.activeRequests).toBe(0);
  });

  it("removes an aborted queued waiter and transfers its slot to later work", async () => {
    const firstGate: { release?: () => void } = {};
    let started = 0;
    const fetchImpl: FetchLike = async (input) => {
      started += 1;
      if (started === 1) {
        await new Promise<void>((resolve) => {
          firstGate.release = resolve;
        });
      }
      const url = String(input);
      const matchedAssetId =
        /proof-assets\/([^/]+)\/verification-bundle/.exec(url)?.[1] ?? ASSET_ID;
      return responseFor(bundleFor(matchedAssetId), url);
    };
    useFetch(fetchImpl);
    const provider = new ParPublicProvider({ maxConcurrency: 1, timeoutMs: 5000 });
    const first = provider.fetchVerificationBundle(ASSET_ID);
    await vi.waitFor(() => expect(started).toBe(1));
    const aborted = new AbortController();
    const second = provider.fetchVerificationBundle(OTHER_ASSET_ID, aborted.signal);
    const third = provider.fetchVerificationBundle("550e8400-e29b-41d4-a716-446655440002");
    aborted.abort();
    await expectProviderError(second, "ABORTED");
    firstGate.release?.();
    await first;
    await third;
    expect(started).toBe(2);
    expect(provider.activeRequests).toBe(0);
  });
});

describe("multi-document retrieval", () => {
  it("fetches bundle and receipt keys in parallel, then fetches signed status", async () => {
    const calls: string[] = [];
    const fetchImpl: FetchLike = async (input, init) => {
      const url = String(input);
      calls.push(`${init?.headers?.Accept}:${url}`);
      if (url === BUNDLE_URL) return responseFor(bundleFor(ASSET_ID), url);
      if (url === JWKS_URL) return responseFor(JSON.stringify(jwksFixture), url);
      if (url === STATUS_URL)
        return responseFor(statusFixture, url, { "content-type": "application/vc+jwt" });
      throw new Error("unexpected URL");
    };
    useFetch(fetchImpl);
    const result = await new ParPublicProvider().fetchPublicRecordEvidence(ASSET_ID);
    expect(result.bundle.asset.proofAssetId).toBe(ASSET_ID);
    expect(result.receipt_jwks.keys).toHaveLength(1);
    expect(result.status_credential?.content_type).toBe("application/vc+jwt");
    expect(calls).toEqual(
      expect.arrayContaining([
        `application/json:${BUNDLE_URL}`,
        `application/json:${JWKS_URL}`,
        `application/vc+jwt:${STATUS_URL}`,
      ]),
    );
  });

  it("preserves the exact audit=omit bundle and fetched status URL at the shared seam", async () => {
    const fetchImpl: FetchLike = async (input, init) => {
      const url = String(input);
      if (url === PRODUCER_BUNDLE_URL) {
        return responseFor(readRawText("producer-omit-wire.json"), url);
      }
      if (url === JWKS_URL) return responseFor(JSON.stringify(jwksFixture), url);
      if (url === STATUS_URL) {
        expect(init?.headers?.Accept).toBe("application/vc+jwt");
        return responseFor(statusFixture, url, { "content-type": "application/vc+jwt" });
      }
      throw new Error("unexpected URL");
    };

    useFetch(fetchImpl);
    const result = await new ParPublicProvider().fetchPublicRecordEvidence(PRODUCER_ASSET_ID);
    expect(PublicVerificationBundleInputSchema.safeParse(result.bundle).success).toBe(true);
    expect(PublicRecordEvidenceInputSchema.safeParse(result).success).toBe(true);
    expect(result.bundle).toEqual(bundleFixture);
    expect(result.bundle.asset.verificationMetadata?.circuit_version).toBe(1);
    expect(result.bundle.statusCheck.checkedAt).toBe("2026-08-30T20:00:00.000Z");
    expect(result.bundle.statusCheck.statusListIndex).toBe("7");
    expect(result.bundle.receipt.claims.status_ref?.statusListIndex).toBe("7");
    expect(result.bundle.receipt.publicJwk?.kid).toBe("par-fixture-retired-2026");
    expect(result.receipt_jwks.keys[0]?.kid).toBe("receipt-fixture");
    expect(result.receipt_jwks.keys[0]?.kid).not.toBe(result.bundle.receipt.publicJwk?.kid);
    expect(result.receipt_jwks.keys[0]?.x).not.toBe(result.bundle.receipt.publicJwk?.x);
    expect(Object.keys(result).sort()).toEqual([
      "bundle",
      "receipt_jwks",
      "status_credential",
      "status_url",
    ]);
    expect(result.bundle.audit).toBeNull();
    expect(result.status_url).toBe(STATUS_URL);
    expect(result.status_url).toBe(result.bundle.receipt.claims.status_ref?.statusListUrl);
    expect(result.status_credential).toEqual({
      credential: statusFixture,
      content_type: "application/vc+jwt",
    });
  });
});

const PRODUCER_REQUIRED_BUNDLE_FIELDS = [
  ["bundle.ok", ["ok"]],
  ["bundle.schemaVersion", ["schemaVersion"]],
  ["bundle.generatedAt", ["generatedAt"]],
  ["bundle.asset", ["asset"]],
  ["bundle.receipt", ["receipt"]],
  ["bundle.statusCheck", ["statusCheck"]],
  ["bundle.provenance", ["provenance"]],
  ["bundle.assurance", ["assurance"]],
  ["bundle.audit", ["audit"]],
  ["bundle.checks", ["checks"]],
  ["asset.proofAssetId", ["asset", "proofAssetId"]],
  ["asset.status.purpose", ["asset", "status", "purpose"]],
  ["asset.status.verificationStatus", ["asset", "status", "verificationStatus"]],
  ["receipt.jws", ["receipt", "jws"]],
  ["receipt.claims", ["receipt", "claims"]],
  ["receipt.publicJwk.kty", ["receipt", "publicJwk", "kty"]],
  ["receipt.publicJwk.crv", ["receipt", "publicJwk", "crv"]],
  ["receipt.publicJwk.x", ["receipt", "publicJwk", "x"]],
  ["receipt.publicJwk.y", ["receipt", "publicJwk", "y"]],
  ["receipt.publicJwk.kid", ["receipt", "publicJwk", "kid"]],
  ["receipt.header.alg", ["receipt", "header", "alg"]],
  ["receipt.header.kid", ["receipt", "header", "kid"]],
  ["receipt.claims.status_ref.statusListUrl", ["receipt", "claims", "status_ref", "statusListUrl"]],
  [
    "receipt.claims.status_ref.statusListIndex",
    ["receipt", "claims", "status_ref", "statusListIndex"],
  ],
  ["receipt.claims.status_ref.statusPurpose", ["receipt", "claims", "status_ref", "statusPurpose"]],
  ["statusCheck.state", ["statusCheck", "state"]],
  ["statusCheck.purpose", ["statusCheck", "purpose"]],
  ["statusCheck.checkedAt", ["statusCheck", "checkedAt"]],
  ["statusCheck.statusListUrl", ["statusCheck", "statusListUrl"]],
  ["statusCheck.statusListIndex", ["statusCheck", "statusListIndex"]],
  ["provenance.environment", ["provenance", "environment"]],
  ["provenance.configurationRevision", ["provenance", "configurationRevision"]],
  ["provenance.binding", ["provenance", "binding"]],
  ["checks.receiptSignature", ["checks", "receiptSignature"]],
  ["checks.assetBinding", ["checks", "assetBinding"]],
  ["checks.audienceBinding", ["checks", "audienceBinding"]],
  ["checks.status", ["checks", "status"]],
  ["checks.auditAnchor", ["checks", "auditAnchor"]],
  ["checks.auditInclusion", ["checks", "auditInclusion"]],
  ["checks.epochSignature", ["checks", "epochSignature"]],
  ["checks.authorizedMintRecord", ["checks", "authorizedMintRecord"]],
  ["checks.assuranceBinding", ["checks", "assuranceBinding"]],
] as const;

describe("PAR artifact schema mutation gates", () => {
  it.each(PRODUCER_REQUIRED_BUNDLE_FIELDS)(
    "rejects the exact producer bundle when required field %s is deleted",
    async (_label, path) => {
      const mutated = structuredClone(bundleFixture);
      deleteField(mutated, path);
      await expectProviderError(
        producerProvider(mutated).fetchPublicRecordEvidence(PRODUCER_ASSET_ID),
        "INVALID_RESPONSE",
      );
    },
  );

  it.each([
    ["receipt_jwks.keys", ["keys"]],
    ["receipt_jwks.keys[0].kty", ["keys", 0, "kty"]],
    ["receipt_jwks.keys[0].crv", ["keys", 0, "crv"]],
    ["receipt_jwks.keys[0].x", ["keys", 0, "x"]],
    ["receipt_jwks.keys[0].y", ["keys", 0, "y"]],
    ["receipt_jwks.keys[0].kid", ["keys", 0, "kid"]],
  ] as const)(
    "rejects the exact producer JWKS when required field %s is deleted",
    async (_label, path) => {
      const mutated = structuredClone(jwksFixture);
      deleteField(mutated, path);
      await expectProviderError(
        producerProvider(bundleFixture, mutated).fetchPublicRecordEvidence(PRODUCER_ASSET_ID),
        "INVALID_RESPONSE",
      );
    },
  );

  it.each([
    ["bundle", []],
    ["asset", ["asset"]],
    ["asset.verificationMetadata", ["asset", "verificationMetadata"]],
    ["asset.status", ["asset", "status"]],
    ["receipt", ["receipt"]],
    ["receipt.publicJwk", ["receipt", "publicJwk"]],
    ["receipt.header", ["receipt", "header"]],
    ["receipt.claims", ["receipt", "claims"]],
    ["receipt.claims.status_ref", ["receipt", "claims", "status_ref"]],
    ["statusCheck", ["statusCheck"]],
    ["provenance", ["provenance"]],
    ["checks", ["checks"]],
  ] as const)("rejects a producer bundle with a nonproducer field at %s", async (_label, path) => {
    const mutated = structuredClone(bundleFixture);
    addMutationField(mutated, path);
    await expectProviderError(
      producerProvider(mutated).fetchPublicRecordEvidence(PRODUCER_ASSET_ID),
      "INVALID_RESPONSE",
    );
  });

  it.each([
    ["receipt_jwks", []],
    ["receipt_jwks.keys[0]", ["keys", 0]],
  ] as const)("rejects a producer JWKS with a nonproducer field at %s", async (_label, path) => {
    const mutated = structuredClone(jwksFixture);
    addMutationField(mutated, path);
    await expectProviderError(
      producerProvider(bundleFixture, mutated).fetchPublicRecordEvidence(PRODUCER_ASSET_ID),
      "INVALID_RESPONSE",
    );
  });

  it.each([
    ["bundle", ["bundle"]],
    ["receipt_jwks", ["receipt_jwks"]],
    ["status_url", ["status_url"]],
  ] as const)(
    "rejects a shared evidence envelope when required field %s is deleted",
    (_label, path) => {
      const mutated = producerEnvelope();
      deleteField(mutated, path);
      expect(() => validatePublicRecordEvidence(mutated)).toThrowError(
        expect.objectContaining({ code: "INVALID_RESPONSE" }),
      );
    },
  );

  it.each([
    ["status_credential.credential", ["status_credential", "credential"]],
    ["status_credential.content_type", ["status_credential", "content_type"]],
  ] as const)(
    "rejects a shared evidence envelope when required field %s is deleted",
    (_label, path) => {
      const mutated = producerEnvelope();
      deleteField(mutated, path);
      expect(() => validatePublicRecordEvidence(mutated)).toThrowError(
        expect.objectContaining({ code: "INVALID_RESPONSE" }),
      );
    },
  );

  it.each([
    ["envelope", []],
    ["envelope.bundle", ["bundle"]],
    ["envelope.receipt_jwks", ["receipt_jwks"]],
    ["envelope.status_credential", ["status_credential"]],
  ] as const)(
    "rejects a shared evidence envelope with a nonproducer field at %s",
    (_label, path) => {
      const mutated = producerEnvelope();
      addMutationField(mutated, path);
      expect(() => validatePublicRecordEvidence(mutated)).toThrowError(
        expect.objectContaining({ code: "INVALID_RESPONSE" }),
      );
    },
  );
});

describe("safe diagnostics", () => {
  it("does not retain identifiers, URLs, body bytes, or upstream exception text in provider errors", async () => {
    const response = responseFor("secret-body-should-not-escape", BUNDLE_URL, {
      "content-type": "text/plain",
    });
    useFetch(fetchReturning(response).fetchImpl);
    const error = await new ParPublicProvider()
      .fetchVerificationBundle(ASSET_ID)
      .catch((value: unknown) => value);
    expect(error).toBeInstanceOf(ParProviderError);
    expect(JSON.stringify(error)).not.toContain(ASSET_ID);
    expect(JSON.stringify(error)).not.toContain("par.myproof.ai");
    expect(JSON.stringify(error)).not.toContain("secret-body");
  });
});

describe("canonical live provider gate", () => {
  it("validates the canonical PAR receipt JWKS through ParPublicProvider when explicitly enabled", async () => {
    // This is intentionally opt-in: ordinary CI is deterministic and uses
    // the bounded fixtures above. An enabled run is a hard live assertion,
    // not a best-effort raw fetch or a skipped network failure.
    if (process.env.MYPROOF_PAR_LIVE_PROVIDER !== "1") return;

    const provider = new ParPublicProvider({
      timeoutMs: 8_000,
      maxJwksBytes: 256 * 1024,
    });
    const jwks = await provider.fetchReceiptJwks();

    expect(jwks.keys.length).toBeGreaterThan(0);
    expect(new Set(jwks.keys.map((key) => key.kid)).size).toBe(jwks.keys.length);
    expect(
      jwks.keys.every(
        (key) =>
          key.kty === "EC" &&
          key.crv === "P-256" &&
          key.alg === "ES256" &&
          typeof key.kid === "string" &&
          key.kid.length > 0 &&
          !Object.prototype.hasOwnProperty.call(key, "d"),
      ),
    ).toBe(true);
    expect(provider.activeRequests).toBe(0);
  });
});

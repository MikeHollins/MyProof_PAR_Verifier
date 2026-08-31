/**
 * Strict base64url helpers used by the verifier.
 *
 * Buffer.from(value, "base64url") is intentionally permissive (it accepts
 * whitespace and a number of non-canonical encodings).  Signed input is an
 * untrusted wire format, so the verifier checks the alphabet and canonical
 * round-trip before decoding.
 */

const BASE64URL = /^[A-Za-z0-9_-]+$/;

export function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

export function decodeBase64Url(value: unknown, field = "base64url"): Uint8Array {
  if (typeof value !== "string" || value.length === 0 || !BASE64URL.test(value)) {
    throw new Error(`INVALID_${field.toUpperCase()}_ENCODING`);
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length === 0 || encodeBase64Url(bytes) !== value) {
    throw new Error(`INVALID_${field.toUpperCase()}_ENCODING`);
  }
  return new Uint8Array(bytes);
}

export function decodeBase64UrlJson(value: unknown, field: string): unknown {
  const bytes = decodeBase64Url(value, field);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new Error(`INVALID_${field.toUpperCase()}_JSON`);
  }
}

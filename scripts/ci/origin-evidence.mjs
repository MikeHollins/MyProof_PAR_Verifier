#!/usr/bin/env node

/**
 * Verify the one canonical PAR origin used by the provider.  This is release
 * and live-network evidence, not a generic DNS/SSRF helper: the host, port,
 * TLS policy, and resolver target are constants and cannot be supplied by a
 * caller.  No HTTP body is fetched and no resolved address is written to
 * evidence.
 */

import { Resolver } from "node:dns";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { isIP } from "node:net";
import { checkServerIdentity, connect as tlsConnect } from "node:tls";

const CANONICAL_HOST = "par.myproof.ai";
const CANONICAL_PORT = 443;
const DNS_TIMEOUT_MS = 10_000;
const TLS_TIMEOUT_MS = 10_000;
const MAX_DNS_ADDRESSES = 32;
const MAX_CERTIFICATE_BYTES = 64 * 1024;
const evidenceDir = resolve(
  process.env.CI_EVIDENCE_DIR ?? join(tmpdir(), "myproof-par-ci-evidence"),
);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function parseIPv4(address) {
  const parts = address.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255))
    return null;
  return parts.map(Number);
}

function isPublicIPv4(address) {
  const octets = parseIPv4(address);
  if (!octets) return false;
  const [a, b, c] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224 || (a === 169 && b === 254)) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && c === 0) return false;
  if (a === 192 && b === 0 && c === 2) return false;
  if (a === 192 && b === 88 && c === 99) return false;
  if (a === 198 && b >= 18 && b <= 19) return false;
  if (a === 198 && b === 51 && c === 100) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

function ipv6ToBigInt(address) {
  if (address.includes("%")) return null;
  let value = address.toLowerCase();
  if (value.includes(".")) {
    const separator = value.lastIndexOf(":");
    if (separator < 0) return null;
    const ipv4 = parseIPv4(value.slice(separator + 1));
    if (!ipv4) return null;
    const high = (ipv4[0] << 8) | ipv4[1];
    const low = (ipv4[2] << 8) | ipv4[3];
    value = `${value.slice(0, separator)}:${high.toString(16)}:${low.toString(16)}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = halves.length === 2 ? 8 - left.length - right.length : 0;
  if (missing < 0 || (halves.length === 1 && left.length !== 8)) return null;
  const groups = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;
  return groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group}`), 0n);
}

function isPublicIPv6(address) {
  const value = ipv6ToBigInt(address);
  if (value === null) return false;
  if (value === 0n || value === 1n) return false;
  // IPv4-mapped IPv6 answers inherit the IPv4 public-address policy.
  if (value >> 32n === 0xffffn) {
    const octets = [
      Number((value >> 24n) & 0xffn),
      Number((value >> 16n) & 0xffn),
      Number((value >> 8n) & 0xffn),
      Number(value & 0xffn),
    ];
    return isPublicIPv4(octets.join("."));
  }
  const firstByte = Number(value >> 120n);
  const firstSevenBits = Number(value >> 121n);
  const firstTenBits = Number(value >> 118n);
  if (firstByte === 0 || firstByte === 0xff) return false;
  if (firstSevenBits === 0b1111110) return false; // fc00::/7 unique local
  if (firstTenBits === 0b1111111010) return false; // fe80::/10 link local
  if (value >> 96n === 0x20010db8n) return false; // 2001:db8::/32 documentation
  return true;
}

function isPublicAddress(address) {
  if (isIP(address) === 4) return isPublicIPv4(address);
  if (isIP(address) === 6) return isPublicIPv6(address);
  return false;
}

function resolverLookup(resolver, method) {
  return new Promise((resolveResult, reject) => {
    resolver[method](CANONICAL_HOST, (error, addresses) => {
      if (error && (error.code === "ENODATA" || error.code === "ENOTFOUND")) {
        resolveResult([]);
        return;
      }
      if (error) reject(error);
      else resolveResult(addresses);
    });
  });
}

async function resolveCanonicalAddresses() {
  const resolver = new Resolver();
  let timeout;
  const lookup = Promise.all([
    resolverLookup(resolver, "resolve4"),
    resolverLookup(resolver, "resolve6"),
  ]).then((families) => [...new Set(families.flat())]);
  const deadline = new Promise((_, reject) => {
    timeout = setTimeout(() => {
      resolver.cancel();
      reject(new Error("canonical DNS lookup timed out"));
    }, DNS_TIMEOUT_MS);
  });
  try {
    return await Promise.race([lookup, deadline]);
  } finally {
    clearTimeout(timeout);
  }
}

function verifyTls(address) {
  const family = isIP(address);
  assert(family === 4 || family === 6, "canonical DNS returned an invalid address family");
  return new Promise((resolveResult, reject) => {
    let settled = false;
    let socket;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      socket?.destroy();
      if (error) reject(error);
      else resolveResult(value);
    };
    const deadline = setTimeout(
      () => finish(new Error("canonical TLS handshake timed out")),
      TLS_TIMEOUT_MS,
    );
    socket = tlsConnect({
      host: CANONICAL_HOST,
      port: CANONICAL_PORT,
      servername: CANONICAL_HOST,
      minVersion: "TLSv1.2",
      maxVersion: "TLSv1.3",
      rejectUnauthorized: true,
      timeout: TLS_TIMEOUT_MS,
      lookup: (_hostname, options, callback) => {
        if (options?.all) callback(null, [{ address, family }]);
        else callback(null, address, family);
      },
    });
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();
      const certificateBytes = certificate.raw?.byteLength ?? 0;
      const identityError = checkServerIdentity(CANONICAL_HOST, certificate);
      const remoteAddress = socket.remoteAddress;
      try {
        assert(
          socket.authorized === true && socket.authorizationError === null,
          "canonical TLS certificate was not authorized",
        );
        assert(identityError === undefined, "canonical TLS hostname validation failed");
        assert(
          socket.getProtocol() === "TLSv1.2" || socket.getProtocol() === "TLSv1.3",
          "canonical TLS version is unsupported",
        );
        assert(
          typeof remoteAddress === "string" && isPublicAddress(remoteAddress),
          "canonical TLS connected to a non-public address",
        );
        assert(
          certificateBytes > 0 && certificateBytes <= MAX_CERTIFICATE_BYTES,
          "canonical TLS certificate exceeds its byte bound",
        );
        finish(null, {
          authorized: true,
          hostnameVerified: true,
          protocol: socket.getProtocol(),
          remoteFamily: socket.remoteFamily ?? null,
          certificateBytes,
        });
      } catch (error) {
        finish(error);
      }
    });
    socket.once("timeout", () => finish(new Error("canonical TLS socket timed out")));
    socket.once("error", (error) => finish(error));
  });
}

async function main() {
  assert(process.argv.length === 2, "canonical origin evidence accepts no caller URL or options");
  const evidence = {
    schema: "myproof.par.ci-canonical-origin.v1",
    mode: "release/live-network-evidence",
    ok: false,
    host: CANONICAL_HOST,
    port: CANONICAL_PORT,
    dns: null,
    tls: null,
    generatedAt: new Date().toISOString(),
  };
  try {
    const addresses = await resolveCanonicalAddresses();
    assert(
      addresses.length > 0 && addresses.length <= MAX_DNS_ADDRESSES,
      "canonical DNS answer set is empty or unbounded",
    );
    const publicAddresses = addresses.filter(isPublicAddress);
    assert(
      publicAddresses.length === addresses.length,
      "canonical DNS returned a non-public address",
    );
    evidence.dns = {
      answerCount: addresses.length,
      publicAnswerCount: publicAddresses.length,
      families: [...new Set(addresses.map((address) => isIP(address)))].sort(
        (left, right) => left - right,
      ),
      allAnswersPublic: true,
    };
    evidence.tls = await verifyTls(publicAddresses[0]);
    evidence.ok = true;
    await mkdir(evidenceDir, { recursive: true });
    await writeFile(
      join(evidenceDir, "origin-evidence.json"),
      `${JSON.stringify(evidence, null, 2)}\n`,
      "utf8",
    );
    process.stdout.write(`${JSON.stringify(evidence)}\n`);
  } catch (error) {
    evidence.error =
      error instanceof Error ? error.message.slice(0, 240) : "canonical origin evidence failed";
    await mkdir(evidenceDir, { recursive: true });
    await writeFile(
      join(evidenceDir, "origin-evidence.json"),
      `${JSON.stringify(evidence, null, 2)}\n`,
      "utf8",
    );
    throw error;
  }
}

main().catch((error) => {
  process.stderr.write(
    `${error instanceof Error ? error.message : "canonical origin evidence failed"}\n`,
  );
  process.exitCode = 1;
});

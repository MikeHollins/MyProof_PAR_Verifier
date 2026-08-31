/**
 * Test-only HTTP bridge for the official MCP conformance runner.
 *
 * The shipped product is stdio-only. This file exists solely because the
 * current conformance runner drives a URL/fetch handler. It mounts the exact
 * same `createMcpServer` factory and verifier seam used by stdio, binds only
 * to loopback, and applies a finite request body bound.
 */

import {
  createServer,
  type IncomingHttpHeaders,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { once } from "node:events";
import { createMcpHandler, type McpHttpHandler } from "@modelcontextprotocol/server";
import {
  MCP_MAX_STDIO_MESSAGE_BYTES,
  createMcpServer,
  type McpServerOptions,
} from "../../../src/mcp/index.js";
import type { VerifyProofAssetRecord } from "../../../src/contracts/index.js";

export interface LoopbackMcpHttpOptions extends McpServerOptions {
  readonly maxRequestBytes?: number;
}

export interface LoopbackMcpHttpServer {
  readonly url: string;
  readonly handler: McpHttpHandler;
  close(): Promise<void>;
}

/** Create the exact SDK fetch handler used by conformance tests. */
export function createConformanceLoopbackHandler(
  verifier: VerifyProofAssetRecord,
  options: LoopbackMcpHttpOptions = {},
): McpHttpHandler {
  return createMcpHandler(() => createMcpServer(verifier, options), {
    // The conformance runner may exercise a 2025 request as well as the
    // current 2026 request. Stateless fallback is test-only and has no
    // state or network authority of its own.
    legacy: "stateless",
    onerror: () => {
      // Diagnostics belong to the test runner's stderr, never its HTTP
      // response body. The production stdio adapter has the same policy.
    },
  });
}

/**
 * Start a loopback HTTP server around the official fetch handler. This is a
 * harness utility, not a package export and not a production transport.
 */
export async function startConformanceLoopbackServer(
  verifier: VerifyProofAssetRecord,
  options: LoopbackMcpHttpOptions = {},
): Promise<LoopbackMcpHttpServer> {
  const maxRequestBytes = options.maxRequestBytes ?? MCP_MAX_STDIO_MESSAGE_BYTES;
  if (
    !Number.isSafeInteger(maxRequestBytes) ||
    maxRequestBytes <= 0 ||
    maxRequestBytes > MCP_MAX_STDIO_MESSAGE_BYTES
  ) {
    throw new RangeError("maxRequestBytes must be a positive bounded integer");
  }

  const handler = createConformanceLoopbackHandler(verifier, options);
  const server = createServer((request, response) => {
    void dispatchHttpRequest(request, response, handler, maxRequestBytes);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") {
    await closeNodeServer(server);
    throw new Error("loopback MCP server did not bind a TCP port");
  }

  return {
    url: `http://127.0.0.1:${address.port}/mcp`,
    handler,
    close: async () => {
      await handler.close();
      await closeNodeServer(server);
    },
  };
}

async function dispatchHttpRequest(
  request: IncomingMessage,
  response: ServerResponse,
  handler: McpHttpHandler,
  maxRequestBytes: number,
): Promise<void> {
  try {
    const body = await readBoundedBody(request, maxRequestBytes);
    const webRequest = new Request(`http://127.0.0.1${request.url ?? "/mcp"}`, {
      method: request.method ?? "GET",
      headers: toHeaders(request.headers),
      body: body.length === 0 ? undefined : body,
      // Required by Node's fetch implementation for a streaming-capable
      // request body, even though this bridge has already buffered it.
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    const webResponse = await handler.fetch(webRequest);
    response.statusCode = webResponse.status;
    webResponse.headers.forEach((value, key) => response.setHeader(key, value));
    response.end(Buffer.from(await webResponse.arrayBuffer()));
  } catch (error) {
    const status = error instanceof LoopbackHttpLimitError ? 413 : 500;
    response.statusCode = status;
    response.setHeader("content-type", "text/plain; charset=utf-8");
    response.end(status === 413 ? "request too large\n" : "loopback MCP harness error\n");
  }
}

function toHeaders(headers: IncomingHttpHeaders): Headers {
  const result = new Headers();
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    result.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  return result;
}

async function readBoundedBody(request: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.byteLength;
    if (size > maxBytes) {
      request.destroy();
      throw new LoopbackHttpLimitError();
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks, size);
}

class LoopbackHttpLimitError extends Error {}

async function closeNodeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

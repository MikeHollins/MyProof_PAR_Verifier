/** Test-only raw JSON-RPC peer; avoids adding a client dependency to the package. */

import {
  InMemoryTransport,
  type JSONRPCMessage,
  type McpServer,
} from "@modelcontextprotocol/server";

export interface RawMcpResponse extends Record<string, unknown> {
  readonly id?: string | number | null;
  readonly result?: Record<string, unknown>;
  readonly error?: Record<string, unknown>;
}

export interface PendingMcpRequest {
  readonly id: string | number;
  readonly response: Promise<RawMcpResponse>;
}

/**
 * Connect a real SDK server to an in-memory transport pair and speak the
 * protocol as a minimal client. This tests MCP wire behavior without
 * introducing an unpinned client package into the published dependency set.
 */
export class InMemoryMcpPeer {
  readonly clientTransport: InMemoryTransport;
  readonly serverTransport: InMemoryTransport;
  private nextId = 1;
  private readonly pending = new Map<string | number, (message: RawMcpResponse) => void>();
  private readonly messages: RawMcpResponse[] = [];

  private constructor(
    readonly server: McpServer,
    clientTransport: InMemoryTransport,
    serverTransport: InMemoryTransport,
  ) {
    this.clientTransport = clientTransport;
    this.serverTransport = serverTransport;
    this.clientTransport.onmessage = (message) => this.onMessage(message);
  }

  static async connect(server: McpServer): Promise<InMemoryMcpPeer> {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const peer = new InMemoryMcpPeer(server, clientTransport, serverTransport);
    await server.connect(serverTransport);
    return peer;
  }

  request(method: string, params: Record<string, unknown> = {}): PendingMcpRequest {
    const id = this.nextId++;
    return this.requestWithId(method, params, id);
  }

  /** Send a request with an explicit string/number id for envelope-bound tests. */
  requestWithId(
    method: string,
    params: Record<string, unknown> = {},
    id: string | number,
  ): PendingMcpRequest {
    if (this.pending.has(id)) throw new Error(`duplicate in-memory MCP request id: ${String(id)}`);
    const response = new Promise<RawMcpResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`in-memory MCP request timed out: ${method}`));
      }, 5_000);
      this.pending.set(id, (message) => {
        clearTimeout(timer);
        resolve(message);
      });
    });
    void this.clientTransport.send({ jsonrpc: "2.0", id, method, params });
    return { id, response };
  }

  notify(method: string, params: Record<string, unknown> = {}): void {
    void this.clientTransport.send({ jsonrpc: "2.0", method, params });
  }

  responsesFor(id: string | number): RawMcpResponse[] {
    return this.messages.filter((message) => message.id === id);
  }

  async close(): Promise<void> {
    for (const resolve of this.pending.values()) {
      resolve({ error: { message: "peer closed" } });
    }
    this.pending.clear();
    await this.clientTransport.close();
    await this.server.close();
  }

  private onMessage(message: JSONRPCMessage): void {
    if (!("id" in message) || (typeof message.id !== "number" && typeof message.id !== "string")) {
      return;
    }
    const response = message as RawMcpResponse;
    this.messages.push(response);
    this.pending.get(message.id)?.(response);
    this.pending.delete(message.id);
  }
}

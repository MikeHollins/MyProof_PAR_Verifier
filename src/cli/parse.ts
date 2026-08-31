import { CliUsageError } from "./errors.js";
import { AssetIdSchema } from "../contracts/index.js";

export interface VerifyInvocation {
  readonly kind: "verify";
  readonly assetId: string;
  readonly requireActive: boolean;
  readonly json: boolean;
}

export interface McpInvocation {
  readonly kind: "mcp";
}

export interface HelpInvocation {
  readonly kind: "help";
}

export type CliInvocation = VerifyInvocation | McpInvocation | HelpInvocation;

export const CLI_USAGE = [
  "Usage:",
  "  myproof-par verify <asset-id> [--require-active] [--json]",
  "  myproof-par mcp",
  "  myproof-par --help",
].join("\n");

export const CLI_HELP = [
  CLI_USAGE,
  "",
  "Verify one public MyProof PAR record using the canonical PAR origin.",
  "",
  "Options:",
  "  --require-active  return exit 10 when the coherent record is not active",
  "  --json            write the canonical report as one JSON document",
  "  -h, --help        show this help text",
].join("\n");

export function parseCliArgs(argv: readonly string[]): CliInvocation {
  if (!Array.isArray(argv) || argv.some((argument) => typeof argument !== "string")) {
    throw new CliUsageError("invalid command line");
  }
  if (argv.length === 0) {
    throw new CliUsageError(`a command is required\n\n${CLI_USAGE}`);
  }

  const [command, ...rest] = argv;
  if (command === "-h" || command === "--help") {
    if (rest.length !== 0)
      throw new CliUsageError(`--help does not accept arguments\n\n${CLI_USAGE}`);
    return { kind: "help" };
  }

  if (command === "mcp") {
    if (rest.length !== 0) throw new CliUsageError(`mcp does not accept arguments\n\n${CLI_USAGE}`);
    return { kind: "mcp" };
  }

  if (command !== "verify") {
    throw new CliUsageError(`unknown command\n\n${CLI_USAGE}`);
  }

  let assetId: string | undefined;
  let requireActive = false;
  let json = false;

  for (const argument of rest) {
    // Keep the public syntax positional: the asset identifier is required
    // immediately after `verify`; only the documented flags may follow it.
    if (assetId === undefined && argument.startsWith("-")) {
      throw new CliUsageError("verify requires the asset-id before options");
    }
    if (argument === "--require-active") {
      if (requireActive) throw new CliUsageError("--require-active may be specified only once");
      requireActive = true;
      continue;
    }
    if (argument === "--json") {
      if (json) throw new CliUsageError("--json may be specified only once");
      json = true;
      continue;
    }
    if (argument === "-h" || argument === "--help") {
      throw new CliUsageError(`verify requires an asset-id\n\n${CLI_USAGE}`);
    }
    if (argument.startsWith("-")) {
      throw new CliUsageError(`unknown option\n\n${CLI_USAGE}`);
    }
    if (assetId !== undefined) {
      throw new CliUsageError("verify accepts exactly one asset-id");
    }
    assetId = validateAssetId(argument);
  }

  if (assetId === undefined) {
    throw new CliUsageError(`verify requires an asset-id\n\n${CLI_USAGE}`);
  }

  return { kind: "verify", assetId, requireActive, json };
}

/**
 * Asset IDs are path components supplied to a fixed provider. The canonical
 * PAR public API uses lowercase UUIDs; matching that grammar here keeps an
 * invalid value out of the provider and prevents path/origin proxy behavior.
 */
export function validateAssetId(value: string): string {
  const parsed = AssetIdSchema.safeParse(value);
  if (!parsed.success) {
    throw new CliUsageError("invalid asset-id; expected a canonical lowercase UUID");
  }
  return parsed.data;
}

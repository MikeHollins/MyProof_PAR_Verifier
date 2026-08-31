#!/usr/bin/env node

/**
 * Remove the compiler output before every build. TypeScript does not delete
 * emitted files for modules removed from the source tree, and stale output
 * would otherwise be eligible for npm pack.
 */

import { rm } from "node:fs/promises";
import { join, resolve } from "node:path";

const packageRoot = resolve(process.cwd());
const distPath = join(packageRoot, "dist");

// Keep the target deliberately derived and narrow: this helper has no path
// argument and cannot be redirected to an unrelated directory by CI input.
if (resolve(distPath) !== resolve(packageRoot, "dist")) {
  throw new Error("refusing to clean an unexpected build directory");
}
await rm(distPath, { recursive: true, force: true });

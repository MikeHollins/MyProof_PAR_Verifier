#!/usr/bin/env node

/**
 * Record reproducible build provenance for the package-smoke artifact.  This
 * is evidence, not a release or npm publication step: the workflow has no
 * registry credentials and this script never mutates a remote service.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const packageRoot = resolve(process.cwd());
const evidenceDir = resolve(
  process.env.CI_EVIDENCE_DIR ?? join(tmpdir(), "myproof-par-ci-evidence"),
);
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function command(command, args) {
  const result = await execFileAsync(command, args, {
    cwd: packageRoot,
    env: {
      ...process.env,
      npm_config_fund: "false",
      npm_config_update_notifier: "false",
    },
    maxBuffer: 2 * 1024 * 1024,
    timeout: 30_000,
  });
  return result.stdout.trim();
}

async function main() {
  const packageJson = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
  const lockBytes = await readFile(join(packageRoot, "package-lock.json"));
  const commit = await command("git", ["rev-parse", "HEAD"]);
  const status = await command("git", ["status", "--porcelain"]);
  const expectedSha = process.env.GITHUB_SHA?.trim();
  if (expectedSha)
    assert(expectedSha === commit, "GITHUB_SHA does not match the checked-out commit");
  if (process.env.CI === "true") assert(status === "", "CI checkout is not clean");

  const packageEvidence = JSON.parse(
    await readFile(join(evidenceDir, "package-smoke.json"), "utf8"),
  );
  assert(packageEvidence.ok === true, "package-smoke evidence is not successful");
  assert(
    packageEvidence.tarball && typeof packageEvidence.tarball.sha256 === "string",
    "package-smoke evidence has no tarball digest",
  );

  const npmVersion = await command(npmCommand, ["--version"]);
  const provenance = {
    schema: "myproof.par.ci-provenance.v1",
    package: { name: packageJson.name, version: packageJson.version },
    source: {
      commit,
      ref: process.env.GITHUB_REF ?? null,
      repository: process.env.GITHUB_REPOSITORY ?? null,
      cleanCheckout: status === "",
    },
    builder: {
      workflow: process.env.GITHUB_WORKFLOW ?? null,
      runId: process.env.GITHUB_RUN_ID ?? null,
      runAttempt: process.env.GITHUB_RUN_ATTEMPT ?? null,
      runner: process.env.RUNNER_NAME ?? null,
      runnerOs: process.env.RUNNER_OS ?? process.platform,
      node: process.version,
      npm: npmVersion,
    },
    inputs: {
      packageLockSha256: createHash("sha256").update(lockBytes).digest("hex"),
    },
    output: {
      tarball: packageEvidence.tarball.filename,
      bytes: packageEvidence.tarball.bytes,
      sha256: packageEvidence.tarball.sha256,
      npmIntegrity: packageEvidence.tarball.integrity,
      npmShasum: packageEvidence.tarball.npmShasum,
    },
    publication: "not performed",
  };
  await mkdir(evidenceDir, { recursive: true });
  await writeFile(
    join(evidenceDir, "provenance.json"),
    `${JSON.stringify(provenance, null, 2)}\n`,
    "utf8",
  );
  process.stdout.write(
    `${JSON.stringify({
      schema: provenance.schema,
      package: provenance.package,
      commit: provenance.source.commit,
      packageLockSha256: provenance.inputs.packageLockSha256,
      tarballSha256: provenance.output.sha256,
      publication: provenance.publication,
    })}\n`,
  );
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "provenance evidence failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});

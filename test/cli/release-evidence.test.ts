import { createHash } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const RELEASE_SCRIPT = fileURLToPath(
  new URL("../../scripts/ci/release-evidence.mjs", import.meta.url),
);
const COMMIT = "0123456789abcdef0123456789abcdef01234567";
const PACKAGE_DIGEST = "a".repeat(64);
const TRUST_DIGEST = "b".repeat(64);

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

async function jsonFile(directory: string, name: string, value: unknown): Promise<void> {
  await writeFile(join(directory, name), `${JSON.stringify(value)}\n`, "utf8");
}

function runRelease(
  cwd: string,
  inputDir: string,
  outputDir: string,
  pathPrefix: string,
  expectedCommit = COMMIT,
): { status: number | null; stdout: string; stderr: string } {
  const result = spawnSync(process.execPath, [RELEASE_SCRIPT], {
    cwd,
    env: {
      ...process.env,
      PATH: `${pathPrefix}:${process.env.PATH ?? ""}`,
      GITHUB_SHA: expectedCommit,
      RELEASE_EVIDENCE_INPUT_DIR: inputDir,
      RELEASE_EVIDENCE_DIR: outputDir,
    },
    encoding: "utf8",
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

describe("release evidence packet", () => {
  it("binds the clean commit, source tree, package, and redacted security outputs once", async () => {
    const root = await mkdtemp(join(tmpdir(), "myproof-release-evidence-test-"));
    const inputDir = join(root, "inputs");
    const outputDir = join(root, "release-evidence");
    const binDir = join(root, "bin");
    const sourceDir = join(root, "src");
    await mkdir(inputDir, { recursive: true });
    await mkdir(binDir, { recursive: true });
    await mkdir(sourceDir, { recursive: true });
    try {
      const packageLock = Buffer.from('{"lockfileVersion":3}\n', "utf8");
      await writeFile(join(root, "package-lock.json"), packageLock);
      await writeFile(join(root, "package.json"), '{"name":"@myproof/par-verifier"}\n', "utf8");
      await writeFile(join(sourceDir, "index.ts"), "export {};\n", "utf8");
      await writeFile(
        join(binDir, "git"),
        [
          "#!/usr/bin/env node",
          "const args = process.argv.slice(2);",
          `if (args.includes("rev-parse")) process.stdout.write("${COMMIT}\\n");`,
          'else if (args.includes("status")) process.stdout.write("");',
          'else if (args.includes("ls-tree")) process.stdout.write("package-lock.json\\0package.json\\0src/index.ts\\0");',
          "else process.exitCode = 1;",
          "",
        ].join("\n"),
        "utf8",
      );
      await chmod(join(binDir, "git"), 0o755);

      const lockfileSha256 = sha256(packageLock);
      const packageInfo = { name: "@myproof/par-verifier", version: "0.1.0" };
      await jsonFile(inputDir, "package-smoke.json", {
        check: "package-smoke",
        ok: true,
        package: { ...packageInfo, rawSensitiveValue: "must-not-enter-packet" },
        tarball: { filename: "package.tgz", bytes: 123, sha256: PACKAGE_DIGEST },
        files: Array.from({ length: 144 }, (_, index) => ({ path: `dist/file-${index}.js` })),
        trustManifest: {
          path: "configs/release-trust-manifest.json",
          bytes: 738,
          sha256: TRUST_DIGEST,
          manifestDigest: TRUST_DIGEST,
          compiledDigestPin: TRUST_DIGEST,
          keyCount: 1,
          loaderAuthenticated: true,
        },
        consumer: {
          publicImport: true,
          trustLoaderImport: true,
          helpExitCode: 0,
          stderrBytes: 0,
          mcp: {
            tarballSha256: PACKAGE_DIGEST,
            initialize: true,
            toolsList: true,
            toolsListSha256: "d".repeat(64),
            toolName: "verify_proof_asset_record",
            toolsCall: "bounded-unavailable",
            cancellation: true,
            eof: true,
            cleanShutdown: true,
            exitCode: 0,
            signal: null,
            stdoutMessages: 4,
            stdoutBytes: 512,
            stderrBytes: 0,
          },
        },
      });
      await jsonFile(inputDir, "origin-evidence.json", {
        schema: "myproof.par.ci-canonical-origin.v1",
        mode: "release/live-network-evidence",
        ok: true,
        host: "par.myproof.ai",
        port: 443,
        dns: { answerCount: 1, publicAnswerCount: 1, families: [4], allAnswersPublic: true },
        tls: {
          authorized: true,
          hostnameVerified: true,
          protocol: "TLSv1.3",
          remoteFamily: "IPv4",
          certificateBytes: 1,
        },
      });
      await jsonFile(inputDir, "dependency-evidence.json", {
        lockfileVersion: 3,
        directDependencyCount: 1,
        transitivePackageCount: 1,
        allDirectSpecsPinned: true,
        allPackageIntegritiesPresent: true,
        allResolvedSourcesPresent: true,
        allResolvedFromNpmRegistry: true,
        missingIntegrity: [],
        missingResolved: [],
        nonRegistrySources: [],
      });
      await jsonFile(inputDir, "dependency-review.json", {
        schema: "myproof.par.ci-dependency-review.v1",
        check: "dependency-review",
        ok: true,
        classification:
          "enforced for pull_request; base-vs-head lock metadata/integrity/license diff gate; vulnerability database review remains npm-audit-owned",
        event: "pull_request",
        baseCommit: "f".repeat(40),
        headCommit: COMMIT,
        changedFiles: ["package-lock.json"],
        changedPackages: ["node_modules/example"],
      });
      await jsonFile(inputDir, "license-evidence.json", { packageCount: 1, missingLicense: [] });
      await jsonFile(inputDir, "npm-audit.json", {
        ok: true,
        vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
      });
      await jsonFile(inputDir, "secret-scan.json", { filesScanned: 3, findings: [] });
      await jsonFile(inputDir, "sbom.cdx.json", {
        bomFormat: "CycloneDX",
        specVersion: "1.5",
        components: [],
        dependencies: [],
      });
      await jsonFile(inputDir, "security-summary.json", {
        check: "security-evidence",
        ok: true,
        package: packageInfo,
        dependency: { packageCount: 1 },
        licenses: { packageCount: 1 },
        secrets: { filesScanned: 3, findings: 0 },
        audit: { ok: true },
        sbom: { format: "CycloneDX", specVersion: "1.5" },
        lockfileSha256,
      });
      await jsonFile(inputDir, "workflow-contract.json", {
        check: "workflow-contract",
        ok: true,
        triggers: ["pull_request", "push", "merge_group", "workflow_dispatch"],
        actionPins: [`actions/checkout@${COMMIT}`],
        defaultPermissions: "contents: read",
        dependencyReview: "not evaluated; npm-audit remains the vulnerability gate",
        windows: "not evaluated; POSIX-only protocol harness",
        durableEvidence:
          "enforced for CI packet upload; only redacted release-evidence JSON/checksum retained 14 days; raw gate inputs and final release attachment remain release-owner responsibilities",
      });
      await jsonFile(inputDir, "provenance.json", {
        schema: "myproof.par.ci-provenance.v1",
        package: packageInfo,
        source: { commit: COMMIT, cleanCheckout: true },
        inputs: { packageLockSha256: lockfileSha256 },
        output: { tarball: "package.tgz", bytes: 123, sha256: PACKAGE_DIGEST },
        builder: { node: "v22.22.3", npm: "10.9.8" },
        publication: "not performed",
      });

      const result = runRelease(root, inputDir, outputDir, binDir);
      expect(result.status).toBe(0);
      const summary = JSON.parse(result.stdout) as {
        ok: boolean;
        commitSha: string;
        packageDigest: string;
        packetSha256: string;
        evidenceFileCount: number;
      };
      expect(summary).toMatchObject({
        check: "release-evidence",
        ok: true,
        commitSha: COMMIT,
        packageDigest: PACKAGE_DIGEST,
        evidenceFileCount: 11,
      });
      const packetBytes = await readFile(join(outputDir, "release-evidence.json"));
      const packet = JSON.parse(packetBytes.toString("utf8")) as {
        schema: string;
        redacted: boolean;
        contractRevision: string;
        source: {
          commitSha: string;
          packageLockSha256: string;
          sourceManifest: { fileCount: number };
        };
        package: { tarball: { sha256: string } };
        evidence: Record<string, { sha256: string }>;
        roi: { collapsed: string[]; intentional: string[] };
      };
      expect(packet).toMatchObject({
        schema: "myproof.par.release-evidence.v1",
        redacted: true,
        contractRevision: "3afbc6fc1a4347a7a583347e70630ccd96c8ddb0",
        source: {
          commitSha: COMMIT,
          packageLockSha256: lockfileSha256,
          sourceManifest: { fileCount: 3 },
        },
        package: { tarball: { sha256: PACKAGE_DIGEST } },
      });
      expect(packet.roi.collapsed.join(" ")).toContain("no second install or consumer run");
      expect(packet.roi.intentional.join(" ")).toContain("protocol hooks stay separate");
      expect(Object.keys(packet.evidence).sort()).toEqual([
        "audit",
        "dependency",
        "dependencyReview",
        "license",
        "origin",
        "packageSmoke",
        "provenance",
        "sbom",
        "secretScan",
        "securitySummary",
        "workflowContract",
      ]);
      expect(packetBytes.toString("utf8")).not.toContain("must-not-enter-packet");
      const checksum = await readFile(join(outputDir, "release-evidence.sha256"), "utf8");
      expect(checksum).toBe(`${sha256(packetBytes)}  release-evidence.json\n`);
      expect(summary.packetSha256).toBe(sha256(packetBytes));

      const packageEvidence = JSON.parse(
        await readFile(join(inputDir, "package-smoke.json"), "utf8"),
      ) as { tarball: { sha256: string }; consumer: { mcp: { tarballSha256: string } } };
      packageEvidence.tarball.sha256 = "c".repeat(64);
      packageEvidence.consumer.mcp.tarballSha256 = packageEvidence.tarball.sha256;
      await jsonFile(inputDir, "package-smoke.json", packageEvidence);
      const packageDrift = runRelease(root, inputDir, outputDir, binDir);
      expect(packageDrift.status).not.toBe(0);
      expect(packageDrift.stderr).toContain("provenance package digest differs");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("fails closed when the package digest or immutable commit drifts", async () => {
    const root = await mkdtemp(join(tmpdir(), "myproof-release-evidence-drift-test-"));
    const inputDir = join(root, "inputs");
    const outputDir = join(root, "release-evidence");
    const binDir = join(root, "bin");
    await mkdir(inputDir, { recursive: true });
    await mkdir(binDir, { recursive: true });
    try {
      await writeFile(join(root, "package-lock.json"), "{}\n", "utf8");
      await writeFile(
        join(binDir, "git"),
        [
          "#!/usr/bin/env node",
          "const args = process.argv.slice(2);",
          `if (args.includes("rev-parse")) process.stdout.write("${COMMIT}\\n");`,
          'else if (args.includes("status")) process.stdout.write("");',
          'else if (args.includes("ls-tree")) process.stdout.write("package-lock.json\\0");',
          "else process.exitCode = 1;",
          "",
        ].join("\n"),
        "utf8",
      );
      await chmod(join(binDir, "git"), 0o755);
      const result = runRelease(root, inputDir, outputDir, binDir, "f".repeat(40));
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("GITHUB_SHA");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("keeps packet assembly in the single package job after the existing smoke gates", async () => {
    const workflow = await readFile(
      fileURLToPath(new URL("../../.github/workflows/ci.yml", import.meta.url)),
      "utf8",
    );
    const packageSection = workflow.match(/\n {2}package:[\s\S]*?(?=\n {2}protocol:|$)/)?.[0] ?? "";
    expect(workflow.match(/run: node scripts\/ci\/release-evidence\.mjs/g)).toHaveLength(1);
    expect(packageSection).toContain("run: node scripts/ci/package-smoke.mjs");
    expect(packageSection).toContain("run: node scripts/ci/security-evidence.mjs");
    expect(packageSection).toContain(
      "RELEASE_EVIDENCE_DIR: ${{ github.workspace }}/release-evidence",
    );
    expect(packageSection).toContain("run: node scripts/ci/release-evidence.mjs");
    expect(packageSection).toContain("run: node scripts/ci/dependency-diff.mjs");
    expect(packageSection).toContain(
      "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    );
    expect(packageSection).toContain("release-evidence/release-evidence.sha256");
    expect(packageSection).toContain("retention-days: 14");
    expect(workflow).not.toMatch(/\n {2}security:\n/);
  });
});

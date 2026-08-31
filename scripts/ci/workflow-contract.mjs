#!/usr/bin/env node

/**
 * Cheap self-trigger and least-privilege guard for the checked-in workflow.
 * Keeping this as a repository script makes workflow edits testable from the
 * same clean install as the package, without introducing a YAML parser just
 * for CI metadata.
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const packageRoot = resolve(process.cwd());
const workflowPath = join(packageRoot, ".github", "workflows", "ci.yml");
const packageJsonPath = join(packageRoot, "package.json");
const evidenceDir = resolve(
  process.env.CI_EVIDENCE_DIR ?? join(tmpdir(), "myproof-par-ci-evidence"),
);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function topLevelTrigger(workflow, trigger) {
  return new RegExp(`^\\s{2}${trigger}:`, "m").test(workflow);
}

function occurrenceCount(value, needle) {
  return value.split(needle).length - 1;
}

async function main() {
  const workflow = await readFile(workflowPath, "utf8");
  const packageJson = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const unitTestCommand = packageJson.scripts?.["test:unit"];
  const allTestCommand = packageJson.scripts?.["test:all"];
  assert(typeof unitTestCommand === "string", "package is missing test:unit");
  assert(allTestCommand === "vitest run", "test:all must cover every Vitest suite");
  for (const selectedPath of [
    "test/cli",
    "test/contracts",
    "test/core",
    "test/crypto",
    "test/service",
    "test/mcp/adapter.test.ts",
    "test/mcp/parity.test.ts",
    "test/provider/http.test.ts",
  ]) {
    assert(unitTestCommand.includes(selectedPath), `test:unit is missing ${selectedPath}`);
  }
  for (const excludedPath of [
    "test/mcp/stdio.integration.test.ts",
    "test/mcp/inspector.test.ts",
    "test/mcp/conformance.test.ts",
  ]) {
    assert(!unitTestCommand.includes(excludedPath), `test:unit must exclude ${excludedPath}`);
  }
  assert(
    /^\s+run:\s+npm run test:unit\s*$/m.test(workflow),
    "quality matrix must run only test:unit",
  );
  assert(
    occurrenceCount(workflow, "run: npm run test:unit") === 1,
    "quality matrix must select test:unit exactly once",
  );
  assert(!/^\s+run:\s+npm test\s*$/m.test(workflow), "quality matrix must not run the full suite");
  assert(
    !workflow.includes("npm run test:all"),
    "workflow must reserve test:all for release/developer use",
  );
  for (const protocolPath of [
    "test/mcp/stdio.integration.test.ts",
    "test/mcp/inspector.test.ts",
    "test/mcp/conformance.test.ts",
  ]) {
    const protocolCommand = `run: npm exec -- vitest run ${protocolPath}`;
    assert(
      occurrenceCount(workflow, protocolCommand) === 1,
      `protocol must run ${protocolPath} once`,
    );
  }
  assert(
    occurrenceCount(workflow, "run: node scripts/ci/package-smoke.mjs") === 1,
    "package job is missing the single empty-consumer smoke",
  );
  assert(
    occurrenceCount(workflow, "run: node scripts/ci/origin-evidence.mjs") === 1,
    "package job is missing the single canonical-origin DNS/TLS evidence probe",
  );
  assert(
    occurrenceCount(workflow, "run: node scripts/ci/dependency-diff.mjs") === 1,
    "package job is missing the base-vs-head dependency lock diff gate",
  );
  const packageSection = workflow.match(/\n {2}package:[\s\S]*?(?=\n {2}protocol:|$)/)?.[0] ?? "";
  assert(
    packageSection.includes("run: node scripts/ci/origin-evidence.mjs"),
    "canonical-origin DNS/TLS evidence must run only in the network-intentional package job",
  );
  assert(
    packageSection.includes("run: node scripts/ci/dependency-diff.mjs"),
    "dependency lock diff must run in the package evidence job",
  );
  const qualityNodeVersions = ["22.19.0", "24.0.0"];
  const qualityOperatingSystems = ["ubuntu-24.04", "macos-14"];
  assert(
    /node:\s*\[22\.19\.0,\s*24\.0\.0\]/m.test(workflow),
    "quality matrix must cover the supported Node 22 and 24 lines",
  );
  assert(
    /os:\s*\[ubuntu-24\.04,\s*macos-14\]/m.test(workflow),
    "quality matrix must retain the truthful Linux and macOS runners",
  );
  const requiredTriggers = ["pull_request", "push", "merge_group", "workflow_dispatch"];
  for (const trigger of requiredTriggers) {
    assert(topLevelTrigger(workflow, trigger), `workflow is missing ${trigger} coverage`);
  }
  assert(/^\s{4}branches:\s*\[main\]/m.test(workflow), "push coverage must include main");
  assert(/\bconcurrency:\s*\n/.test(workflow), "workflow concurrency is missing");
  assert(/\bcancel-in-progress:\s*true\b/.test(workflow), "workflow cancellation is not enabled");
  assert(
    /\bpermissions:\s*\n\s+contents:\s*read\b/.test(workflow),
    "workflow must default to contents: read",
  );
  assert(
    !/^\s+paths(?:-ignore)?:/m.test(workflow),
    "path filters would create an unverified self-trigger gap",
  );

  const actionUses = [...workflow.matchAll(/^\s+uses:\s*([^\s#]+)\s*$/gm)].map((match) => match[1]);
  assert(actionUses.length > 0, "workflow has no action references to verify");
  for (const action of actionUses) {
    assert(/@[0-9a-f]{40}$/.test(action), `workflow action is not pinned to a commit: ${action}`);
  }
  assert(
    occurrenceCount(
      workflow,
      "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
    ) === 1,
    "release evidence must use the single SHA-pinned upload-artifact action",
  );
  assert(
    packageSection.includes("release-evidence/release-evidence.json") &&
      packageSection.includes("release-evidence/release-evidence.sha256") &&
      packageSection.includes("retention-days: 14") &&
      packageSection.includes("if-no-files-found: error"),
    "release evidence upload must include the packet and checksum with bounded retention",
  );
  assert(
    !/permissions:[\s\S]*?\b(?:contents|actions|packages|pull-requests):\s*write\b/.test(workflow),
    "workflow grants an unnecessary write permission",
  );

  const evidence = {
    check: "workflow-contract",
    ok: true,
    workflow: ".github/workflows/ci.yml",
    triggers: requiredTriggers,
    pushBranches: ["main"],
    pathFilters: "none",
    concurrency: "cancel-in-progress",
    actionPins: actionUses,
    defaultPermissions: "contents: read",
    testSelection: {
      quality: unitTestCommand,
      fullSuite: "npm run test:all",
      protocol: [
        "test/mcp/stdio.integration.test.ts",
        "test/mcp/inspector.test.ts",
        "test/mcp/conformance.test.ts",
      ],
      package: "node scripts/ci/package-smoke.mjs (one empty consumer)",
      dependencyReview: "node scripts/ci/dependency-diff.mjs (one PR base/head lock diff)",
      releaseNetwork: "node scripts/ci/origin-evidence.mjs (fixed par.myproof.ai; one)",
    },
    invocationCounts: {
      quality: {
        nodeVersions: qualityNodeVersions,
        operatingSystems: qualityOperatingSystems,
        matrixCells: qualityNodeVersions.length * qualityOperatingSystems.length,
        unitInvocationsPerCell: 1,
        unitInvocationsTotal: qualityNodeVersions.length * qualityOperatingSystems.length,
      },
      protocol: {
        stdio: 1,
        inspector: 1,
        conformance: 1,
        total: 3,
      },
      package: { emptyConsumer: 1, canonicalOriginDnsTls: 1 },
    },
    dependencyReview:
      "enforced for pull_request; base-vs-head lock metadata/integrity/license diff gate; vulnerability database review remains npm-audit-owned",
    windows: "not evaluated; stdio package smoke currently targets POSIX runners",
    durableEvidence:
      "enforced for CI packet upload; only redacted release-evidence JSON/checksum retained 14 days; raw gate inputs and final release attachment remain release-owner responsibilities",
  };
  await mkdir(evidenceDir, { recursive: true });
  await writeFile(
    join(evidenceDir, "workflow-contract.json"),
    `${JSON.stringify(evidence, null, 2)}\n`,
    "utf8",
  );
  process.stdout.write(`${JSON.stringify(evidence)}\n`);
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "workflow contract failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});

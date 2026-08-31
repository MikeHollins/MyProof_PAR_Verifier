#!/usr/bin/env node

/**
 * Assemble one redacted, checksummed release-evidence packet.
 *
 * The package, security, origin, workflow, and provenance gates produce the
 * input JSON files. This script only reads those results; it never runs npm,
 * installs a consumer, publishes, or contacts a remote service. The packet is
 * written to a caller-selected workspace directory (the default is
 * ./release-evidence), not to runner.temp, so the generated record can be
 * retained or committed by the release owner after review.
 */

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const packageRoot = resolve(process.cwd());
const scriptPath = fileURLToPath(import.meta.url);
const contractRevision = "3afbc6fc1a4347a7a583347e70630ccd96c8ddb0";
const maxEvidenceBytes = 16 * 1024 * 1024;
const maxSourceFiles = 10_000;
const evidenceFiles = [
  ["packageSmoke", "package-smoke.json"],
  ["origin", "origin-evidence.json"],
  ["dependency", "dependency-evidence.json"],
  ["dependencyReview", "dependency-review.json"],
  ["license", "license-evidence.json"],
  ["audit", "npm-audit.json"],
  ["secretScan", "secret-scan.json"],
  ["sbom", "sbom.cdx.json"],
  ["securitySummary", "security-summary.json"],
  ["workflowContract", "workflow-contract.json"],
  ["provenance", "provenance.json"],
];
const roi = {
  essential: [
    "one clean lockfile install and build per CI job",
    "four quality cells for the supported Node and POSIX runner matrix",
    "one real stdio, Inspector, and conformance hook",
    "one package/empty-consumer, security, origin, provenance, and packet path",
  ],
  collapsed: [
    "package smoke, security evidence, provenance, and packet assembly share the Node 22 package job",
    "release-evidence reads existing gate outputs and performs no second install or consumer run",
  ],
  intentional: [
    "quality cells repeat deterministic tests only for runtime/OS coverage",
    "protocol hooks stay separate because lifecycle, Inspector, and conformance are distinct oracles",
  ],
};

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function object(value, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} is malformed`);
  return value;
}

function digest(value, label) {
  assert(typeof value === "string" && /^[a-f0-9]{64}$/.test(value), `${label} is not SHA-256`);
  return value;
}

function commitDigest(value, label) {
  assert(typeof value === "string" && /^[a-f0-9]{40}$/.test(value), `${label} is not a commit SHA`);
  return value;
}

function hashBytes(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function safePath(value, label) {
  assert(
    typeof value === "string" &&
      value.length > 0 &&
      !value.startsWith("/") &&
      !value.includes("\\") &&
      !value.split("/").includes(".."),
    `${label} is not a safe relative path`,
  );
  return value;
}

function pathInside(parent, child) {
  const childRelative = relative(parent, child);
  return (
    childRelative === "" ||
    (!childRelative.startsWith("..") &&
      !isAbsolute(childRelative) &&
      !childRelative.includes(`..${sep}`))
  );
}

function safeError(error) {
  if (error instanceof Error) return error.message.slice(0, 240);
  return "release evidence failed";
}

async function runGit(args) {
  try {
    const result = await execFileAsync("git", ["-C", packageRoot, ...args], {
      cwd: packageRoot,
      env: { ...process.env },
      maxBuffer: 8 * 1024 * 1024,
      timeout: 30_000,
    });
    return result.stdout;
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? error.code : null;
    throw new Error(`git ${args.join(" ")} failed (${String(code ?? "unknown")})`, {
      cause: error,
    });
  }
}

async function readBounded(path, label) {
  const fileStat = await lstat(path);
  assert(fileStat.isFile(), `${label} is not a regular file`);
  assert(fileStat.size <= maxEvidenceBytes, `${label} exceeds the evidence byte bound`);
  return readFile(path);
}

async function readJson(inputDir, filename) {
  const safeName = safePath(filename, "evidence filename");
  const bytes = await readBounded(join(inputDir, safeName), safeName);
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(`${safeName} is not valid JSON`);
  }
  return { value: object(value, safeName), bytes: bytes.byteLength, sha256: hashBytes(bytes) };
}

async function sourceManifest() {
  const tree = await runGit(["ls-tree", "-r", "--name-only", "-z", "HEAD"]);
  const paths = tree
    .split("\0")
    .filter((path) => path.length > 0)
    .map((path) => safePath(path, "tracked source path"));
  assert(
    paths.length > 0 && paths.length <= maxSourceFiles,
    "tracked source tree is empty or unbounded",
  );
  paths.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));

  const files = [];
  const aggregate = createHash("sha256");
  for (const path of paths) {
    const absolutePath = join(packageRoot, path);
    const fileStat = await lstat(absolutePath);
    assert(fileStat.isFile(), `tracked source path is not a regular file: ${path}`);
    const bytes = await readFile(absolutePath);
    const sha256 = hashBytes(bytes);
    files.push({ path, bytes: bytes.byteLength, sha256 });
    aggregate.update(`${path}\0${sha256}\n`, "utf8");
  }
  return {
    algorithm: "sha256",
    fileCount: files.length,
    aggregateSha256: aggregate.digest("hex"),
    files,
  };
}

async function sourceIdentity() {
  const commit = commitDigest(
    (await runGit(["rev-parse", "--verify", "HEAD^{commit}"])).trim(),
    "checked-out commit",
  );
  const expectedCommit = process.env.GITHUB_SHA?.trim();
  if (expectedCommit !== undefined && expectedCommit !== "") {
    assert(commitDigest(expectedCommit, "GITHUB_SHA") === commit, "GITHUB_SHA does not match HEAD");
  }
  const status = await runGit(["status", "--porcelain=v1", "--untracked-files=all"]);
  assert(status === "", "release evidence requires a clean checkout before packet creation");
  const manifest = await sourceManifest();
  const lockfile = manifest.files.find((entry) => entry.path === "package-lock.json");
  assert(lockfile, "tracked source manifest is missing package-lock.json");
  return {
    commitSha: commit,
    expectedCommitSha: expectedCommit && expectedCommit !== "" ? expectedCommit : null,
    cleanCheckout: true,
    sourceManifest: manifest,
    packageLockSha256: lockfile.sha256,
  };
}

function packageSummary(value) {
  assert(value.check === "package-smoke" && value.ok === true, "package-smoke did not pass");
  const packageInfo = object(value.package, "package-smoke package");
  const tarball = object(value.tarball, "package-smoke tarball");
  const trustManifest = object(value.trustManifest, "package-smoke trust manifest");
  const packageName = packageInfo.name;
  const packageVersion = packageInfo.version;
  assert(
    typeof packageName === "string" && typeof packageVersion === "string",
    "package metadata is missing",
  );
  const tarballSha256 = digest(tarball.sha256, "package tarball digest");
  const manifestDigest = digest(trustManifest.manifestDigest, "trust manifest digest");
  const compiledDigestPin = digest(trustManifest.compiledDigestPin, "compiled trust digest pin");
  assert(manifestDigest === compiledDigestPin, "package trust manifest and compiled pin differ");
  assert(trustManifest.loaderAuthenticated === true, "package trust loader is not authenticated");
  assert(
    trustManifest.path === "configs/release-trust-manifest.json",
    "package trust manifest path is not canonical",
  );
  assert(
    Number.isSafeInteger(trustManifest.bytes) && trustManifest.bytes > 0,
    "package trust manifest size is invalid",
  );
  assert(
    Number.isSafeInteger(trustManifest.keyCount) &&
      trustManifest.keyCount > 0 &&
      trustManifest.keyCount <= 32,
    "package trust key count is invalid",
  );
  assert(
    Number.isSafeInteger(tarball.bytes) && tarball.bytes > 0,
    "package tarball size is invalid",
  );
  const tarballFilename = safePath(tarball.filename, "package tarball filename");
  assert(!tarballFilename.includes("/"), "package tarball filename must be a basename");
  const files = Array.isArray(value.files) ? value.files : [];
  assert(files.length > 0, "package file count is invalid");
  const consumer = object(value.consumer, "package-smoke consumer");
  assert(
    consumer.publicImport === true &&
      consumer.trustLoaderImport === true &&
      consumer.helpExitCode === 0 &&
      consumer.stderrBytes === 0,
    "consumer package smoke is incomplete",
  );
  const mcp = object(consumer.mcp, "package-smoke MCP consumer");
  assert(
    mcp.initialize === true &&
      mcp.toolsList === true &&
      mcp.cancellation === true &&
      mcp.eof === true &&
      mcp.cleanShutdown === true,
    "consumer MCP lifecycle smoke is incomplete",
  );
  assert(
    mcp.toolName === "verify_proof_asset_record" &&
      (mcp.toolsCall === "canonical-report" || mcp.toolsCall === "bounded-unavailable"),
    "consumer MCP tools/call evidence is incomplete",
  );
  assert(
    mcp.tarballSha256 === tarballSha256,
    "consumer MCP evidence is bound to a different tarball",
  );
  digest(mcp.toolsListSha256, "consumer MCP tools/list digest");
  assert(mcp.exitCode === 0 && mcp.signal === null, "consumer MCP did not shut down cleanly");
  assert(
    Number.isSafeInteger(mcp.stdoutMessages) &&
      mcp.stdoutMessages > 0 &&
      Number.isSafeInteger(mcp.stdoutBytes) &&
      mcp.stdoutBytes > 0 &&
      mcp.stderrBytes === 0,
    "consumer MCP stream evidence is invalid",
  );
  return {
    name: packageName,
    version: packageVersion,
    tarball: {
      filename: tarballFilename,
      bytes: tarball.bytes,
      sha256: tarballSha256,
    },
    fileCount: files.length,
    trustManifest: {
      path: trustManifest.path,
      bytes: trustManifest.bytes,
      sha256: digest(trustManifest.sha256, "trust manifest file digest"),
      manifestDigest,
      compiledDigestPin,
      keyCount: trustManifest.keyCount,
      loaderAuthenticated: true,
    },
    consumer: {
      publicImport: true,
      trustLoaderImport: true,
      help: true,
      mcp: {
        tarballSha256: mcp.tarballSha256,
        initialize: true,
        toolsList: true,
        toolsListSha256: mcp.toolsListSha256,
        toolName: mcp.toolName,
        toolsCall: mcp.toolsCall,
        cancellation: true,
        eof: true,
        cleanShutdown: true,
        exitCode: 0,
        signal: null,
        stdoutMessages: mcp.stdoutMessages,
        stdoutBytes: mcp.stdoutBytes,
        stderrBytes: 0,
      },
    },
  };
}

function securitySummary(records, packageInfo, packageLockSha256) {
  const dependency = records.dependency.value;
  const license = records.license.value;
  const audit = records.audit.value;
  const secretScan = records.secretScan.value;
  const sbom = records.sbom.value;
  const summary = records.securitySummary.value;
  assert(dependency.allDirectSpecsPinned === true, "dependency specs are not all pinned");
  assert(
    dependency.allPackageIntegritiesPresent === true,
    "dependency integrity evidence is incomplete",
  );
  assert(
    dependency.allResolvedSourcesPresent === true,
    "dependency resolved-source evidence is incomplete",
  );
  assert(
    dependency.allResolvedFromNpmRegistry === true,
    "dependency source is not limited to npm registry",
  );
  assert(
    Array.isArray(dependency.missingIntegrity) && dependency.missingIntegrity.length === 0,
    "dependency integrity gaps remain",
  );
  assert(
    Array.isArray(dependency.missingResolved) && dependency.missingResolved.length === 0,
    "dependency resolution gaps remain",
  );
  assert(
    Array.isArray(dependency.nonRegistrySources) && dependency.nonRegistrySources.length === 0,
    "non-registry dependency remains",
  );
  assert(
    Array.isArray(license.missingLicense) && license.missingLicense.length === 0,
    "license metadata is incomplete",
  );
  assert(audit.ok === true, "npm audit did not pass");
  const vulnerabilities = object(audit.vulnerabilities, "npm audit vulnerabilities");
  for (const severity of ["info", "low", "moderate", "high", "critical", "total"]) {
    assert(vulnerabilities[severity] === 0, `npm audit has ${severity} vulnerabilities`);
  }
  assert(
    Array.isArray(secretScan.findings) && secretScan.findings.length === 0,
    "secret scan found material",
  );
  assert(
    sbom.bomFormat === "CycloneDX" && sbom.specVersion === "1.5",
    "SBOM format/version is unsupported",
  );
  assert(
    summary.check === "security-evidence" && summary.ok === true,
    "security summary did not pass",
  );
  const packageSummaryInfo = object(summary.package, "security summary package");
  assert(
    packageSummaryInfo.name === packageInfo.name &&
      packageSummaryInfo.version === packageInfo.version,
    "security summary package identity differs",
  );
  assert(
    summary.lockfileSha256 === packageLockSha256,
    "security lockfile digest differs from source manifest",
  );
  assert(
    summary.dependency?.packageCount === dependency.transitivePackageCount,
    "dependency counts differ",
  );
  assert(summary.licenses?.packageCount === license.packageCount, "license counts differ");
  assert(summary.secrets?.findings === 0, "security summary reports secret findings");
  assert(summary.audit?.ok === true, "security summary reports an audit failure");
  assert(
    summary.sbom?.format === sbom.bomFormat && summary.sbom?.specVersion === sbom.specVersion,
    "SBOM summaries differ",
  );
  return {
    dependency: {
      lockfileVersion: dependency.lockfileVersion,
      directDependencyCount: dependency.directDependencyCount,
      transitivePackageCount: dependency.transitivePackageCount,
      allDirectSpecsPinned: true,
      allPackageIntegritiesPresent: true,
      allResolvedSourcesPresent: true,
      allResolvedFromNpmRegistry: true,
    },
    license: { packageCount: license.packageCount, missingLicenseCount: 0 },
    audit: { ok: true, vulnerabilities },
    secretScan: { filesScanned: secretScan.filesScanned, findings: 0 },
    sbom: {
      bomFormat: sbom.bomFormat,
      specVersion: sbom.specVersion,
      componentCount: Array.isArray(sbom.components) ? sbom.components.length : null,
      dependencyCount: Array.isArray(sbom.dependencies) ? sbom.dependencies.length : null,
    },
    summary: {
      node: summary.node,
      npm: summary.npm,
      dependencyPackageCount: summary.dependency.packageCount,
      licensePackageCount: summary.licenses.packageCount,
      secretFilesScanned: summary.secrets.filesScanned,
      lockfileSha256: summary.lockfileSha256,
    },
  };
}

function originSummary(value) {
  assert(
    value.schema === "myproof.par.ci-canonical-origin.v1" && value.ok === true,
    "canonical origin evidence did not pass",
  );
  assert(
    value.mode === "release/live-network-evidence",
    "canonical origin evidence mode is unexpected",
  );
  assert(value.host === "par.myproof.ai" && value.port === 443, "canonical origin is not fixed");
  const dns = object(value.dns, "origin DNS evidence");
  const tls = object(value.tls, "origin TLS evidence");
  assert(
    dns.allAnswersPublic === true && dns.publicAnswerCount === dns.answerCount,
    "origin DNS answers are not all public",
  );
  assert(
    tls.authorized === true && tls.hostnameVerified === true,
    "origin TLS hostname is not authenticated",
  );
  assert(
    tls.protocol === "TLSv1.2" || tls.protocol === "TLSv1.3",
    "origin TLS protocol is unsupported",
  );
  return {
    host: "par.myproof.ai",
    port: 443,
    dns: {
      answerCount: dns.answerCount,
      publicAnswerCount: dns.publicAnswerCount,
      families: dns.families,
      allAnswersPublic: true,
    },
    tls: {
      authorized: true,
      hostnameVerified: true,
      protocol: tls.protocol,
      remoteFamily: tls.remoteFamily,
      certificateBytes: tls.certificateBytes,
    },
  };
}

function dependencyReviewSummary(value) {
  assert(
    value.check === "dependency-review" && value.ok === true,
    "dependency-review lock diff did not pass",
  );
  assert(typeof value.classification === "string", "dependency-review classification is missing");
  if (value.classification.startsWith("enforced")) {
    assert(
      value.classification.includes("base-vs-head") && value.classification.includes("npm-audit"),
      "dependency-review enforced classification is incomplete",
    );
  } else {
    assert(
      value.classification.startsWith("not evaluated") &&
        value.classification.includes("npm-audit"),
      "dependency-review non-PR classification is not truthful",
    );
  }
  return {
    classification: value.classification,
    event: typeof value.event === "string" ? value.event : null,
    baseCommit: typeof value.baseCommit === "string" ? value.baseCommit : null,
    headCommit: typeof value.headCommit === "string" ? value.headCommit : null,
    changedFileCount: Array.isArray(value.changedFiles) ? value.changedFiles.length : 0,
    changedPackageCount: Array.isArray(value.changedPackages) ? value.changedPackages.length : 0,
  };
}

function workflowSummary(value) {
  assert(
    value.check === "workflow-contract" && value.ok === true,
    "workflow contract did not pass",
  );
  const actionPins = Array.isArray(value.actionPins) ? value.actionPins : [];
  assert(
    actionPins.length > 0 && actionPins.every((pin) => /^[^@\s]+@[a-f0-9]{40}$/.test(pin)),
    "workflow action pins are incomplete",
  );
  assert(
    value.defaultPermissions === "contents: read",
    "workflow permissions are not least privilege",
  );
  assert(
    typeof value.dependencyReview === "string" &&
      /^(?:enforced|advisory|unavailable|not evaluated)\b/.test(value.dependencyReview),
    "workflow dependency-review classification is missing or invalid",
  );
  assert(
    typeof value.windows === "string" &&
      /^(?:enforced|advisory|unavailable|not evaluated)\b/.test(value.windows),
    "workflow Windows classification is missing or invalid",
  );
  assert(
    typeof value.durableEvidence === "string" && value.durableEvidence.startsWith("enforced"),
    "workflow durable evidence upload is not enforced",
  );
  return {
    triggers: value.triggers,
    pushBranches: value.pushBranches,
    pathFilters: value.pathFilters,
    concurrency: value.concurrency,
    actionPins,
    defaultPermissions: value.defaultPermissions,
    testSelection: value.testSelection,
    invocationCounts: value.invocationCounts,
    dependencyReview: value.dependencyReview,
    windows: value.windows,
    durableEvidence: value.durableEvidence,
  };
}

function provenanceSummary(value, identity, packageInfo, packageDigest) {
  assert(value.schema === "myproof.par.ci-provenance.v1", "provenance schema is unexpected");
  const source = object(value.source, "provenance source");
  const output = object(value.output, "provenance output");
  const inputs = object(value.inputs, "provenance inputs");
  const packageValue = object(value.package, "provenance package");
  assert(
    source.commit === identity.commitSha && source.cleanCheckout === true,
    "provenance commit/clean state is invalid",
  );
  assert(
    packageValue.name === packageInfo.name && packageValue.version === packageInfo.version,
    "provenance package identity differs",
  );
  assert(output.sha256 === packageDigest, "provenance package digest differs");
  assert(
    inputs.packageLockSha256 === identity.packageLockSha256,
    "provenance lockfile digest differs",
  );
  assert(output.tarball === packageInfo.tarball.filename, "provenance package filename differs");
  assert(
    Number.isSafeInteger(output.bytes) && output.bytes > 0,
    "provenance package size is invalid",
  );
  assert(value.publication === "not performed", "provenance evidence must not publish");
  return {
    schema: value.schema,
    commitSha: identity.commitSha,
    cleanCheckout: true,
    packageLockSha256: identity.packageLockSha256,
    tarball: {
      filename: output.tarball,
      bytes: output.bytes,
      sha256: packageDigest,
    },
    builder: { node: value.builder?.node ?? null, npm: value.builder?.npm ?? null },
    publication: "not performed",
  };
}

function packetFromRecords(identity, records) {
  const packageInfo = packageSummary(records.packageSmoke.value);
  const security = securitySummary(records, packageInfo, identity.packageLockSha256);
  const dependencyReview = dependencyReviewSummary(records.dependencyReview.value);
  const origin = originSummary(records.origin.value);
  const workflow = workflowSummary(records.workflowContract.value);
  const provenance = provenanceSummary(
    records.provenance.value,
    identity,
    packageInfo,
    packageInfo.tarball.sha256,
  );
  const summaries = {
    packageSmoke: packageInfo,
    origin,
    dependency: security.dependency,
    dependencyReview,
    license: security.license,
    audit: security.audit,
    secretScan: security.secretScan,
    sbom: security.sbom,
    securitySummary: security.summary,
    workflowContract: workflow,
    provenance,
  };
  const evidence = {};
  for (const [key, filename] of evidenceFiles) {
    const record = records[key];
    evidence[key] = {
      file: filename,
      bytes: record.bytes,
      sha256: record.sha256,
      summary: summaries[key],
    };
  }
  return {
    schema: "myproof.par.release-evidence.v1",
    redacted: true,
    redaction:
      "Whitelisted summaries and SHA-256 digests only; raw evidence, credentials, tokens, and network addresses are excluded.",
    generatedAt: new Date().toISOString(),
    contractRevision,
    roi,
    source: identity,
    package: packageInfo,
    bindings: {
      commitToProvenance: true,
      packageDigestToProvenance: true,
      packageLockToSecurityAndProvenance: true,
      trustManifestToCompiledPin: true,
      dependencyReviewToPacket: true,
      durableEvidenceUpload: workflow.durableEvidence,
      everyInputChecksummed: true,
    },
    evidence,
  };
}

async function atomicWrite(path, bytes) {
  const temporaryPath = `${path}.tmp-${process.pid}`;
  try {
    await writeFile(temporaryPath, bytes, { mode: 0o644 });
    await rename(temporaryPath, path);
  } catch (error) {
    await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}

export async function buildReleaseEvidence({ inputDir, outputDir } = {}) {
  const resolvedInputDir = resolve(
    inputDir ??
      process.env.RELEASE_EVIDENCE_INPUT_DIR ??
      process.env.CI_EVIDENCE_DIR ??
      join(packageRoot, ".ci-evidence"),
  );
  const resolvedOutputDir = resolve(
    outputDir ?? process.env.RELEASE_EVIDENCE_DIR ?? join(packageRoot, "release-evidence"),
  );
  assert(
    resolvedOutputDir !== packageRoot,
    "release evidence output must use a dedicated directory",
  );
  assert(
    resolvedOutputDir !== resolvedInputDir,
    "release evidence output must not overwrite its inputs",
  );
  const runnerTemp = process.env.RUNNER_TEMP?.trim();
  if (runnerTemp !== undefined && runnerTemp !== "") {
    assert(
      !pathInside(resolve(runnerTemp), resolvedOutputDir),
      "release evidence output must not use runner.temp as durable storage",
    );
  }
  const identity = await sourceIdentity();
  const records = {};
  for (const [key, filename] of evidenceFiles)
    records[key] = await readJson(resolvedInputDir, filename);
  const packet = packetFromRecords(identity, records);
  const packetBytes = Buffer.from(`${JSON.stringify(packet, null, 2)}\n`, "utf8");
  const packetSha256 = hashBytes(packetBytes);
  await mkdir(resolvedOutputDir, { recursive: true });
  const packetPath = join(resolvedOutputDir, "release-evidence.json");
  const checksumPath = join(resolvedOutputDir, "release-evidence.sha256");
  await atomicWrite(packetPath, packetBytes);
  await atomicWrite(checksumPath, Buffer.from(`${packetSha256}  release-evidence.json\n`, "utf8"));
  return {
    check: "release-evidence",
    ok: true,
    schema: packet.schema,
    commitSha: identity.commitSha,
    sourceManifestSha256: identity.sourceManifest.aggregateSha256,
    packageDigest: packet.package.tarball.sha256,
    packetSha256,
    evidenceFileCount: evidenceFiles.length,
    output: relative(packageRoot, packetPath),
    roi: { collapsed: roi.collapsed, intentional: roi.intentional },
  };
}

async function main() {
  const result = await buildReleaseEvidence();
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (resolve(process.argv[1] ?? "") === resolve(scriptPath)) {
  main().catch((error) => {
    process.stderr.write(`${safeError(error)}\n`);
    process.exitCode = 1;
  });
}

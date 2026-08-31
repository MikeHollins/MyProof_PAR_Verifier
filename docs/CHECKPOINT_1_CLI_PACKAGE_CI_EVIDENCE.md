# Checkpoint 1 CLI, package, and CI evidence

Status: local clean-copy checkpoint evidence only; not remote CI or release
sign-off.

Collected from a source-only copy of
`/private/tmp/MyProof_PAR_Verifier-20260830` on 2026-08-30 (America/New_York),
after the immutable-vector formatting and suspension/rotation/parity tests had
settled. The contract authority is revision
`3afbc6fc1a4347a7a583347e70630ccd96c8ddb0` of
`docs/plans/PAR_VERIFIER_CLI_MCP_EXECUTION_CONTRACT.md` in the AgeVerify
repository.

## Clean-copy identity

The proof copy is
`/private/tmp/myproof-par-clean-checkpoint1-final5.d5rwUE`. It was copied before
installing dependencies or building, with `.git`, `node_modules`, `dist`,
coverage, npm caches/logs, and update-notifier state excluded. The pre-install
assertions found no `.git`, `node_modules`, or `dist`; the source manifest had
103 files and aggregate SHA-256
`913912cda90b38758563171de387e85374c658ed1de92e112c66beb7232ae3bd`.
This record was added after that snapshot, so it is intentionally not part of
the recorded source-manifest hash.

## Exact clean-copy commands and results

All commands below ran from the proof copy. The cache was external to the
copy, at `/private/tmp/myproof-par-clean-final5-npm-cache.tItgj8`.

| Command                                                                                                       | Result                                                                                         |
| ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `npm ci --ignore-scripts --no-audit --no-fund --cache /private/tmp/myproof-par-clean-final5-npm-cache.tItgj8` | PASS, exit 0; 327 packages added                                                               |
| `npm run schema:check`                                                                                        | PASS, exit 0 (runner permission was required for tsx's temporary IPC socket)                   |
| `npm run format:check`                                                                                        | PASS, exit 0; all files matched                                                                |
| `npm run lint`                                                                                                | PASS, exit 0                                                                                   |
| `npm run check`                                                                                               | PASS, exit 0                                                                                   |
| `npm run build`                                                                                               | PASS, exit 0                                                                                   |
| `for script in scripts/ci/*.mjs; do node --check "$script"; done`                                             | PASS, exit 0; every CI helper parsed                                                           |
| `node scripts/ci/workflow-contract.mjs`                                                                       | PASS, exit 0; required triggers, action pins, matrix, least privilege, and selections verified |
| `npm run test:unit -- --reporter=dot`                                                                         | PASS, 17 files / 291 tests                                                                     |
| `npm run test:all -- --reporter=dot`                                                                          | PASS, 20 files / 296 tests                                                                     |

The quality selection includes `test/cli`, contracts, core, crypto, service,
MCP adapter/parity, and provider HTTP tests. The full-suite command remains
available as `test:all` and is not duplicated in each quality matrix cell.

## Protocol, package, origin, and security results

The three protocol hooks ran once each from the clean copy, with no duplicate
full-suite invocation:

```text
npm exec -- vitest run test/mcp/stdio.integration.test.ts  # PASS, 1 file / 2 tests
npm exec -- vitest run test/mcp/inspector.test.ts           # PASS, 1 file / 2 tests
npm exec -- vitest run test/mcp/conformance.test.ts        # PASS, 1 file / 1 test
```

The single package command was:

```text
CI=true npm_config_cache=/private/tmp/myproof-par-clean-final5-npm-cache.tItgj8 \
CI_EVIDENCE_DIR=/private/tmp/myproof-par-clean-final5-package-evidence \
node scripts/ci/package-smoke.mjs
```

It passed with exit 0: 144 packed files, 125,355-byte tarball, tarball
SHA-256
`b6756af9845676eb9758b31a7c1992deb0be07eba8ae40483407251519f2b3ec`, and
`publicImport=true`, `consumerHelp=true`. The packed schema set contained only
JSON artifacts, the bin mode was 0755, and the only `configs/` path was the
public release manifest. The empty consumer additionally proved the installed
manifest (738 bytes, SHA-256
`ac918983338eafa600c6bc45b566f7b60f8b7c164128b680e890d7b6d4491ab7`) matched
its canonical digest, the compiled
`RELEASE_TRUST_MANIFEST_DIGEST_PIN`
(`bb2f6db506741d6ca8818bec9a025650578ffc6d49ba7ac14c7caefd7b4d7620`), and
the loader's authenticated state. The trust ring was non-empty with one key;
all three digest/authentication checks passed.

The fixed-host live evidence command was run once, separately from
deterministic quality:

```text
CI=true CI_EVIDENCE_DIR=/private/tmp/myproof-par-clean-final5-package-evidence \
node scripts/ci/origin-evidence.mjs
```

It passed with `ok=true`: `par.myproof.ai` resolved to two IPv4 answers, both
classified public; TLS was authorized with hostname verification, TLS 1.3,
and a 1,275-byte certificate. No resolved address was written to evidence.
This is release/live-network evidence, not a generic resolver claim or a
deterministic unit gate.

The security evidence command was:

```text
CI=true npm_config_cache=/private/tmp/myproof-par-clean-final5-npm-cache.tItgj8 \
CI_EVIDENCE_DIR=/private/tmp/myproof-par-clean-final5-security-evidence \
node scripts/ci/security-evidence.mjs
```

It passed with exit 0: 387 lockfile packages and licenses, 16 direct
dependencies, 103 files scanned with zero secret findings, npm audit clear,
CycloneDX SBOM 1.5 generated, and lockfile SHA-256
`61b54ad658e817691420809e5b4b9c02f7a857492eb55b0265bea7c5d6960d05`.

## Workflow disposition and remaining gap

`node scripts/ci/workflow-contract.mjs` reports four quality cells (Node
22.19.0 and 24.0.0 on Ubuntu 24.04 and macOS 14), one `test:unit` invocation
per cell, three protocol invocations total, one empty-consumer package smoke,
and one canonical-origin DNS/TLS probe. Triggers cover pull requests, pushes
to `main`, merge queue, and manual dispatch; concurrency cancels superseded
runs; permissions are `contents: read`; checkout and setup-node are pinned to
the checked-in immutable SHAs. Dependency-review is enforced on pull requests
by a base-vs-head lock metadata/integrity/license diff; vulnerability-database
review remains npm-audit-owned, and
Windows is explicitly not evaluated because the current stdio harness targets
POSIX runners.

Gate inputs are written to runner-local temporary directories. The workflow assembles a redacted checksummed packet in the workspace and uploads only that packet and checksum for bounded 14-day retention.
The upload does not retain raw SBOM/license/audit/secret/provenance/package inputs and is not a final release attachment or publication record.
This local record therefore does not establish that a remote run or uploaded artifact has completed.
The workflow configuration is still only locally inspected in this record; remote CI execution, uploaded packet identity, and final publication remain unobserved.

The provenance command was intentionally run from the source-only copy:

```text
CI=true CI_EVIDENCE_DIR=/private/tmp/myproof-par-clean-final5-package-evidence \
node scripts/ci/provenance-evidence.mjs
```

It failed with exit 1 at `git rev-parse HEAD`:
`fatal: not a git repository (or any of the parent directories): .git`.
This is the expected and only clean-copy provenance gap: the proof copy
deliberately omitted Git metadata. After the integration commit exists, rerun
the package smoke and then provenance from a clean checkout with
`CI=true GITHUB_SHA=<integration-commit>` and the same evidence directory;
the checked-out commit must match `GITHUB_SHA` and the checkout must be clean.

No commit, push, package publication, remote mutation, or artifact upload was
performed for this record.

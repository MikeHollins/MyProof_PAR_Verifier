# Checkpoint 1 evidence index

Status: local checkpoint index only; not release evidence.

This index is the routing page for the checkpoint records currently present in
the standalone worktree. It records disposition and command entry points but
does not duplicate the detailed hashes, fixtures, mutation cases, or protocol
observations in the linked records. The immutable authority is revision
`3afbc6fc1a4347a7a583347e70630ccd96c8ddb0` of
`docs/plans/PAR_VERIFIER_CLI_MCP_EXECUTION_CONTRACT.md` in the AgeVerify
repository.

## Evidence map

| Lane                   | Durable record or source                                                                                                                                                                                                                                                                                                                                 | Authoritative command entry points                                                                                                                                                                                                                                                                                                                                                                                        | Current disposition                                                                                                                                                                                                                                                                                   |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Contracts and provider | [contracts/provider evidence](CHECKPOINT_1_CONTRACTS_PROVIDER_EVIDENCE.md); [foundation contract](FOUNDATION_CONTRACT.md)                                                                                                                                                                                                                                | `shasum -a 256 ...`; `cmp -s ...`; `npm run check`; `npm run build`; `npm run schema:check`; `npm run lint`; `npm exec -- vitest run test/contracts test/provider/http.test.ts`; owned-path Prettier check                                                                                                                                                                                                                | PASS for the recorded local contract/provider scope. The linked record contains the exact fixture hashes, schema/export checks, and local-versus-release boundaries.                                                                                                                                  |
| Core and service       | [core/cryptography evidence](CHECKPOINT_1_CORE_CRYPTO_EVIDENCE.md); [service-facade evidence](CHECKPOINT_1_SERVICE_EVIDENCE.md); source/test anchors remain [core verification tests](../test/core/verify.test.ts) and [immutable fixture test](../test/core/immutable-fixture.test.ts).                                                                 | `npm run check -- --pretty false`; `npm run build`; `npm run lint -- --no-warn-ignored`; `npm run format:check`; `npm run test:unit -- --reporter=dot`; focused core/crypto/service/parity Vitest command recorded in the linked core record                                                                                                                                                                              | PASS for the linked local core/cryptography/service records. These records do not close full-repository, remote-CI, or release gates.                                                                                                                                                                 |
| CLI, package, and CI   | [CLI/package/CI evidence](CHECKPOINT_1_CLI_PACKAGE_CI_EVIDENCE.md); source/test anchors: [CLI tests](../test/cli/run.test.ts), [package smoke](../scripts/ci/package-smoke.mjs), [provenance evidence](../scripts/ci/provenance-evidence.mjs), [workflow contract](../scripts/ci/workflow-contract.mjs), and [CI workflow](../.github/workflows/ci.yml). | `npm run test:unit`; `npm run test:all`; `npm exec -- vitest run test/mcp/stdio.integration.test.ts`; `npm exec -- vitest run test/mcp/inspector.test.ts`; `npm exec -- vitest run test/mcp/conformance.test.ts`; `node scripts/ci/package-smoke.mjs`; `node scripts/ci/origin-evidence.mjs`; `node scripts/ci/security-evidence.mjs`; `node scripts/ci/provenance-evidence.mjs`; `node scripts/ci/workflow-contract.mjs` | LOCAL PASS for the clean-copy quality, protocol, package, fixed-origin, security, and workflow-contract gates. Provenance is intentionally NOT PROVEN because the source-only copy has no `.git`/`HEAD`; remote CI enforcement, durable evidence upload, and published-artifact evidence remain open. |
| MCP                    | [MCP evidence](CHECKPOINT_1_MCP_EVIDENCE.md)                                                                                                                                                                                                                                                                                                             | `npm run build`; `npm run schema:check`; scoped Prettier/ESLint; `npx vitest run test/mcp/adapter.test.ts test/mcp/parity.test.ts test/mcp/stdio.integration.test.ts test/mcp/inspector.test.ts test/mcp/conformance.test.ts --reporter=dot`; package-smoke command recorded in the linked record                                                                                                                         | PASS for the linked scoped local MCP record. It is not a release sign-off and does not certify the missing parent/core/provider/CI/deployment gates.                                                                                                                                                  |

## Open hard gates

The following remain open or are not represented by a final durable record in
this worktree:

- remote CI evidence; a later root-level local `npm run test:all` handoff
  reports 20 files and 296 tests passed, but the linked core/cryptography/
  service records prove only their listed local suites and the handoff is not
  release evidence;
- final CLI golden outputs, exit-code, cancellation, and clean-shutdown evidence;
- remote CI execution, enforcement classification, and supported-platform cells;
- final `npm pack`/empty-consumer, provenance, SBOM, dependency/license, and
  published-artifact verification as release evidence;
- PAR historical-key retention and `audit=omit` runtime/query
  non-invocation evidence;
- website canonical-origin configuration, immutable deployment revision, and
  bounded canonical live verification;
- key-rotation and rollback rehearsal evidence; and
- the independent audit disposition and contract score gate of at least 97/100
  with no unresolved hard finding.

Local PASS entries in the map establish only the scope stated by their linked
records. They must not be combined into a claim of full implementation,
release, deployment, or production health.

## Reproduction authority

Run the immutable-contract lookup before interpreting any command or record:

```text
git -C /Users/michaelhollins/Applications/AgeVerify show 3afbc6fc1a4347a7a583347e70630ccd96c8ddb0:docs/plans/PAR_VERIFIER_CLI_MCP_EXECUTION_CONTRACT.md
```

The linked lane records are the authoritative local result details. This index
intentionally does not restate their outputs or turn a missing record into an
inference.

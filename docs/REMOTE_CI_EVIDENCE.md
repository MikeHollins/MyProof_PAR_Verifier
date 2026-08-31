# Remote CI and enforcement evidence

This record is a point-in-time, commit-bound account of the standalone
repository's remote CI controls. It does not by itself claim package
publication, PAR deployment, website deployment, rollback, or final release
completion.

## Protected integration

- Repository: `MikeHollins/MyProof_PAR_Verifier`
- Ruleset: `main release gates` (`21900305`)
- Enforcement: `active`
- Protected ref: `refs/heads/main`
- Bypass actors: none; the authenticated repository owner cannot bypass it
- History controls: branch deletion and non-fast-forward updates are blocked
- Integration control: pull requests are required
- Required-check policy: strict and required on branch creation
- Required-check producer: GitHub Actions integration `15368`

The required contexts are:

1. `Quality (ubuntu-24.04, Node 22.19.0)`
2. `Quality (ubuntu-24.04, Node 24.0.0)`
3. `Quality (macos-14, Node 22.19.0)`
4. `Quality (macos-14, Node 24.0.0)`
5. `Package, security, and release evidence`
6. `Inspector and MCP conformance hooks`

The effective-rules endpoint for `main` returned all four rules above. The
legacy branch-protection endpoint is not authoritative for this repository
because enforcement is owned by Repository Rulesets.

## Observed event delivery

### Workflow-only pull request

- Pull request: `#1`
- Base commit: `847bb8973a135f88262d4bc4ee8bbe7d5f0755b4`
- Head commit: `06b9e90cc377c95528f1e8ceb9fb811239fe339a`
- Synthetic tested merge commit: `7a46daa12ba3dbc14af2dab564a0c08a94c21365`
- Run: `33358930771`
- Result: all six required jobs passed with zero check-run annotations
- Dependency review: enforced base-to-head comparison; 387 packages and 15
  direct dependencies on both sides, with no dependency changes
- Lockfile SHA-256:
  `f9561dde28e5b27c45508aad99626453755407a86be3ffbd3114f1eeb042ef22`

This run proves that changing the workflow itself triggers the workflow.

### Protected-main push

- Merge commit: `c0f1f13c747694aa92912fda2408be940b04466e`
- Run: `33359310836`
- Result: all six required jobs passed
- Artifact: `9746170274`
- Artifact archive SHA-256:
  `11796408484e759ccd4a44ec6233c7f2d5105cd02452debc820d11091a200fbc`
- Artifact expiry: `2026-09-14T05:07:02Z`

The ruleset became active before pull request `#1` was merged, and the merge
occurred only after all six required check runs were successful.

### Manual dispatch

- Commit: `c0f1f13c747694aa92912fda2408be940b04466e`
- Run: `33359484264`
- Result: all six jobs passed
- Artifact: `9746225313`
- Artifact archive SHA-256:
  `c4295311ca04d0c683c0f874cc40a02b87f9c37ddabb5c752db150fd418f2a10`
- Artifact expiry: `2026-09-14T05:10:02Z`

## Evidence boundaries

- GitHub's artifact SHA-256 identifies the uploaded archive. It is distinct
  from the checksum inside the release-evidence packet.
- The 14-day redacted workflow artifact is operational evidence, not the final
  durable release record. Final durability requires an immutable release
  attachment and an independently verified download hash.
- `merge_group` delivery is not claimed unless merge queue is configured and an
  actual `merge_group` event is observed.
- The pull request that adds this file is the docs-only changed-path delivery
  probe. Its run and eventual protected-main push must be added to final
  machine-bound evidence after they complete.

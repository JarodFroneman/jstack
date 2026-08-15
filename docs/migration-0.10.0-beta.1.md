# Migrating To The JStack v0.10.0-beta.1 Unvalidated Prerelease

## Status

This document describes the explicitly unvalidated Beta.1 prerelease. ADR 0022
permits the exact `v0.10.0-beta.1` tag, GitHub prerelease, and exact-version
Codex installation before the Proof Study runs. It is not a validation
announcement: ADR 0021's 18-image, 216-attempt, 432-review, scoring, and final
evidence gates remain pending, and no uplift or production-readiness claim is
enabled.

## Candidate changes

- All installable manifests, the standalone and umbrella MCP servers, and MCP
  `initialize.serverInfo.version` use the single `0.10.0-beta.1` identity.
- The installed surface remains exactly five command plugins and 52 canonical
  MCP tools. The Python core remains standard-library-only and supports Python
  3.9 and newer.
- The Proof Plane remains uninstalled under `evals/` and
  `tools/proof_plane/`. It adds no product command, MCP tool, dependency,
  reviewer authority, or model client to the installed runtime.
- Private study inputs and outputs stay under the permission-restricted,
  gitignored `.jstack-evals/beta1-codex-proof-study` root.

## Validate a candidate checkout

From the repository root, run:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/sync_artifacts.py --check
python3 scripts/check_contract_compatibility.py
python3 scripts/check_product_boundaries.py
git diff --check
```

The checks must confirm one version across all six plugin manifests and both
MCP server copies, exact artifact synchronization, alpha.9 compatibility,
five commands, 52 tools, a standard-library core, and no packaged Proof Plane
authority.

## Local development installation

Do not replace a shared/global Codex installation merely to inspect this
candidate. Use a disposable `CODEX_HOME` and the transactional installer:

```bash
candidate_codex_home="$(mktemp -d)"
python3 scripts/install.py --codex-home "$candidate_codex_home"
python3 "$candidate_codex_home/mcp/jstack/smoke_test.py"
```

Delete or archive the disposable directory after inspection. A local
candidate installation does not satisfy the Beta.1 study or validation gate.

## Unvalidated global installation

Install globally only from the exact annotated `v0.10.0-beta.1` GitHub
prerelease after its release checks pass. Preserve the previous shared MCP,
five dedicated plugin sources and caches, Codex configuration, marketplace
state, and `~/.jstack` state as one rollback unit. Follow Layout B in
`docs/installation.md`, keep the umbrella plugin uninstalled, and verify that
all five plugins plus MCP initialization report `0.10.0-beta.1` with exactly
52 canonical tools. Installation changes availability only; it does not
satisfy or waive the deferred study.

## Private study readiness (deferred)

The uninstalled maintainer CLI now has closed, fixed-path status surfaces for
the remaining study prerequisites. They are safe to inspect without starting
the study or authorizing a release:

```bash
python3 -m tools.proof_plane.cli study-doctor
python3 -m tools.proof_plane.cli runtime-bootstrap status
python3 -m tools.proof_plane.cli qualify-images status
python3 -m tools.proof_plane.cli task-artifacts status
python3 -m tools.proof_plane.cli prepare-registration-candidate status
```

The dedicated Apple runtime lifecycle uses `/usr/local/bin/container` 1.2.2
and a fixed fresh per-user Beta.1 app root. `runtime-bootstrap start` is an
explicit later maintainer action; ordinary code validation neither installs
Apple container nor starts or adopts a host service. The start gate also
requires user-owned, non-symlink app-root parents and rejects both account- and
install-level `container` configuration overrides before creating the store.

After the genuine image, curator, reviewer, and verifier inputs exist,
`prepare-study` imports the one-key evidence-verifier roster alongside the
other fixed private inputs. `prepare-registration-candidate build` then
derives a private, deterministic 18-task/216-run candidate. Its separate
`publish` action writes only the reviewed registration bundle to fixed
repository paths: it deliberately creates no Git tag, authorizes no attempt,
and publishes no release. None of these actions should be run merely to call
the product code complete.

## Compatibility

- Existing alpha.9 public request contracts, persisted-state markers, legacy
  aliases, and the five-plugin layout remain readable.
- Existing alpha.10 Proof Foundation fixtures remain historical fixtures and
  keep their original version binding; they are not rewritten as Beta.1
  evidence.
- Any receipt bound to an older server version, Git commit, policy, tool
  catalog, or plugin payload must be treated as stale and reacquired.

## Rollback

Before any local candidate installation, retain the prior `CODEX_HOME` plugin,
MCP, and configuration targets. The transactional installer restores all
targets if an installation step fails. For a manual rollback, reinstall the
last trusted alpha.10 checkout with the same installer, restart Codex, and
verify that MCP initialization and every plugin manifest again report
`0.10.0-alpha.10`.

Rollback invalidates candidate-bound QA, security, audit, loop, program,
launch, and release receipts. Preserve private `.jstack-evals` evidence; never
rewrite or reinterpret it under the older runtime.

## Deferred validation work

Beta.1 remains unvalidated until all 18 images qualify, all 216 attempts reach
write-once terminals, all 432 primary human signatures and any adjudications
verify, and the locked scorer plus independent evidence verifier succeed.
Until then, the prerelease must retain its unvalidated label and publish no
study or uplift result. Beta.2 work requires a separate explicit approval.

# Migrating To JStack v0.10.0-alpha.9

JStack v0.10.0-alpha.9 implements Phase 8 of the verified Audit Mastery
roadmap: Enterprise Audit Lead.

## What Changed

- Audit curriculum content version is now 10.
- Stage 8 uses the existing `jstack.audit.result.v1`, SARIF 2.1.0, and the new
  closed `jstack.audit.enterprise-risk-register.v1` contract.
- The canonical MCP inventory remains 52 tools; Stage 8 is evaluated through
  the existing mastery-record path and adds no broad execution surface.
- Stage 8 accepts only `audit-report.md`, `audit-result.json`, `audit.sarif`,
  and `risk-register.json` at their exact `.jstack-training/` paths.
- A fresh current-session, exact-HEAD, complete-repository release-audit
  receipt must match the finalized result's coverage, findings, counts,
  suppression expiries, threshold, status, and evaluation time.
- Every finding requires one priority-first risk entry. Open risk needs an
  owner, reason, and future target; accepted risk must exactly reproduce all
  finalized governance fields.
- The evaluator regenerates deterministic SARIF and canonical Markdown and
  derives go/no-go from the complete release-audit result.
- The controls drill compares a current passing release audit against a prior
  passed, Git-immutable Stage 8 baseline and rejects blocker, severity, or
  priority regressions.

## Evidence Boundary

The four Stage 8 outputs are necessarily written after audit finalization, so
only those exact paths may explain project-fingerprint drift. Any application,
configuration, Git, or additional training-path change fails closed.

Stage 8 consumes current release-audit, QA, and security receipts directly
between JStack tools. The user does not copy an approval token, signing command,
challenge, or confirmation digest into a terminal. Audit remains read-only and
does not create the candidate, implement controls, accept risk, commit, publish,
release, deploy, or access production.

## Compatibility

- The five public commands and 52-tool MCP inventory are unchanged.
- Mastery profile schema v3 is unchanged. Existing attempts retain their
  original curriculum digest; new Stage 8 attempts bind curriculum version 10.
- Python 3.9+ and the standard-library-only MCP runtime remain supported.
- Legacy `gstack_*` aliases remain available.
- Existing Stage 0 through Stage 7 evidence contracts are unchanged.

## Upgrade

1. Check out the immutable `v0.10.0-alpha.9` tag.
2. Back up the current MCP, plugin sources/caches, Codex configuration, and
   `~/.jstack` state.
3. Run `python3 scripts/sync_artifacts.py --check` and
   `python3 -m unittest discover -s tests -v`.
4. Run `python3 scripts/install.py` for the shared Codex installation or
   reinstall the five dedicated plugins from the personal marketplace.
5. Restart Codex or open a new task.
6. Verify the MCP initialize response reports `0.10.0-alpha.9`, `tools/list`
   exposes 52 canonical tools, all five plugins report the same version, and
   the umbrella plugin remains uninstalled when using the dedicated layout.

## Meaning Of A Pass

A Stage 8 pass proves bounded Git identity, receipt/result reconciliation,
risk-register completeness, report projection, decision, QA/security, and
baseline/candidate comparison integrity. It does not prove vulnerability
absence, exploitability, zero-day detection, standards compliance, risk
acceptance, release authorization, deployment safety, production safety, or
production authority.

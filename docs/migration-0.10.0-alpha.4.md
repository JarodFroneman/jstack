# Migrating To JStack v0.10.0-alpha.4

JStack v0.10.0-alpha.4 implements Phase 3 of the verified Audit Mastery
roadmap: Security and Threat-Modelling Auditor. This remains a prerelease. The
new stage validates a static evidence package; it does not execute exploits,
patch vulnerabilities, certify standards compliance, or declare a system
secure.

## What Changed

- The Audit curriculum content version is now 5.
- Stage 3 uses the closed `jstack.audit.security-findings.v1` schema.
- Its exact artifacts are `threat-model.md`, `security-findings.json`, and
  `abuse-cases.md` beneath `.jstack-training/`.
- The report binds the current Git HEAD/tree plus both narrative hashes.
- Every STRIDE category must be classified. Unsupported coverage, gaps,
  incomplete status, stale or unused evidence, dangling or unused objects, and
  non-reciprocal references fail closed.
- Assets, adversaries, trust boundaries, controls, abuse cases, attack paths,
  findings, and standards mappings must use current hash-verified tracked
  source citations.
- Every blocker requires a verified reachable path; the seeded drill requires
  at least one critical blocker. Speculative high-severity claims fail.
- Verified findings map reciprocally to pinned MITRE CWE 4.20, NIST SP 800-218
  v1.1, OWASP ASVS 5.0.0, or OWASP Top 10:2025 references.
- JSON and both narratives reject recognized secret-like values. Evaluation
  records only metadata, counts, failure codes, and a digest.
- Stage 3 requires two consecutive independent deterministic passes at 80 or
  above. Because it is static-only, it does not require a QA receipt.
- The MCP tool inventory remains 50 and no new top-level command is added.

## Safety Boundary

Stage 3 treats repository content as untrusted data and permits no repository
execution, live exploitation, retained exploit payload, network authority,
secret access, remediation, publication, release, deployment, or production
action. Suspected novel vulnerabilities remain private coordinated-disclosure
material.

A pass proves only that the submitted threat-model package met JStack's
deterministic structure, binding, traceability, and safety contract. It does
not prove vulnerability absence, exploitability, zero-day detection, semantic
truth, legal or standards compliance, remediation safety, release readiness,
or production security.

## Upgrade

1. Check out the immutable `v0.10.0-alpha.4` tag.
2. Back up the installed MCP, five plugin sources/caches, Codex configuration,
   marketplace configuration, and `~/.jstack` state.
3. Run `python3 scripts/sync_artifacts.py --check`.
4. Run `python3 -m unittest discover -s tests -v`.
5. Run `python3 mcp/jstack/smoke_test.py`.
6. Install with `python3 scripts/install.py` or reinstall the five dedicated
   plugins and shared MCP using `docs/installation.md`.
7. Restart Codex and confirm the MCP and all five plugins report
   `0.10.0-alpha.4`, the MCP exposes 50 canonical tools, and the umbrella
   plugin remains absent in the dedicated layout.

Existing mastery profiles migrate without resetting completed stages or
attempt history. Earlier attempt records keep their original curriculum
digest; new Stage 3 attempts bind curriculum version 5.

## Rollback

Restore the MCP directory, five plugin sources/caches, and Codex configuration
from the same pre-upgrade backup, then restart Codex and rerun the installed
smoke test. Preserve `~/.jstack` state unless a separate recovery procedure
requires otherwise.

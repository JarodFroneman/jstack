# JStack Audit System

## Purpose

`jstack-audit` is a read-only workflow for evidence-bound frontend, backend,
security, reliability, architecture, performance, supply-chain, testability,
operations, data-integrity, and API compatibility review.

It separates two responsibilities:

- the command agent performs semantic review, generates candidates, and tries
  to disprove them;
- the deterministic MCP binds repository evidence, validates structured
  findings and coverage, calculates the result, and emits stable outputs.

An audit receipt proves the deterministic collection and validation facts it
contains. It is not proof that a model-authored semantic claim is true.

## Invocation

Verified forms depend on distribution:

~~~text
$jstack-audit [scope] [options]                  # umbrella or legacy skill
$jstack-audit:jstack-audit [scope] [options]     # dedicated plugin
/prompts:jstack-audit [scope] [options]
~~~

`/jstack-audit` is the intended palette label, but palette rendering is
client-dependent and requires an installed-client restart test before it is
claimed. Use the matching skill form with `help`, `--help`, or `?` for usage
without inspecting a repository.

Options:

~~~text
--profile quick|standard|deep|release
--focus correctness,security,maintainability,architecture,performance,supply-chain,testability,operations,data-integrity,api-compatibility
--base <trusted-ref>
--fail-on critical|high|medium|low|info|none
--format markdown|json|sarif|all
--verify
--learning-mode off|embedded|coach|assessment
--team-mode single-lead|smart-subagents|full-team
~~~

Unknown flags and invalid paths fail closed. Audit mode never edits project
code, deploys, publishes, or records mastery unless separately requested.
`--fail-on` cannot weaken the enterprise `high` floor; weaker requests,
including `critical` and `none`, are clamped to the effective policy threshold.

## Profiles

| Profile | Scope and evidence contract |
| --- | --- |
| `quick` | Changed files and release range, diff hygiene, current secret scan, and obvious correctness/security regressions. No repository-controlled execution and no whole-repository clean claim. |
| `standard` | Changed modules, direct callers/dependencies, associated tests, affected configuration/interfaces, all applicable domains, and explicit unsupported coverage. |
| `deep` | Whole repository within declared caps, architecture/trust boundaries, all domains, required approved test and static-analysis adapters, and an independent challenge pass. Missing or failed mandatory analyzers make the result incomplete. |
| `release` | Exact distinct pre-release baseline, complete repository/current-tree and release-range scope, complete required domains, required tests/static/dependency adapters, policy-required QA/security evidence, no truncation or stale evidence, and an explicit go/no-go with residual risk. |

A profile fixes its required evidence before findings are evaluated. Missing
required evidence cannot be downgraded into a pass.

## Lifecycle

### Start

`jstack_audit`:

1. resolves the canonical Git root or advisory artifact-only root;
2. validates the baseline, scope, profile, policy, controls, and limits;
3. records HEAD, workspace fingerprint, policy/control digests, adapter
   inventory, and inspected-input manifest;
4. composes deterministic health, review, and the existing secret-scan result;
5. returns a signed, session-local audit token plus required coverage and gaps.

The start operation discovers curated analyzers but does not execute them by
default. Quick rejects every execution approval. Deep and release first return
their exact approval subjects; the operator reviews those subjects and starts a
new bound session with approvals. A failed, capped, stale, or unavailable
required analyzer makes coverage incomplete.

### Review

The command agent uses two passes:

1. Candidate generation cites an exact location and violated contract.
2. Challenge and verification checks guards, callers, tests, reachability,
   mitigating controls, and safe reproductions.

Each retained finding declares one verification state:

- `test-reproduced`
- `tool-confirmed`
- `source-proven`
- `reasoned-strong-evidence`
- `unverified-hypothesis`

An unverified hypothesis is an observation and cannot block release.

### Finalize

`jstack_audit_finalize`:

1. verifies the token, server session, expiry, repository and policy state;
2. validates coverage, paths, source ranges, finding contracts, stable
   fingerprints, duplicates, suppressions, and accepted risk;
3. derives exactly one result: `pass`, `fail`, `incomplete`, or `error`;
4. renders only the requested JSON, Markdown, and/or SARIF 2.1.0 artifacts,
   plus a bounded executive/result envelope;
5. issues a Git-bound audit receipt when the evidence is eligible.

`pass` means complete required coverage with no verified finding at or above the
policy failure threshold. `fail` means complete coverage with a verified
blocker. Missing, truncated, stale, raced, or inconclusive required evidence is
`incomplete`; invalid input or a system failure is `error`. Neither incomplete
nor error can become pass.

## Finding Contract

Findings use `jstack.audit.finding.v1` and keep these decisions separate:

- severity: impact if the claim is true;
- confidence: strength of evidence;
- priority: organizational action order.

Material findings include an exact repository-relative path and range, factual
claim, evidence references, reachable failure/exploit path, preconditions,
impact, likelihood, remediation, verification plan, and residual risk. Security
findings may use CVSS 4.0. Correctness, architecture, maintainability, and
performance findings must not.

Locations retain an optional source symbol. Remediation output contains a
recommended change plus explicit alternatives and trade-offs arrays; simple
string input is normalized into that structure with empty optional arrays.

A material verification state also requires at least one complete evidence item
bound to the active audit subject. `test-reproduced` additionally requires that
bound item to be marked reproducible. Stale, missing, or differently bound
evidence deterministically downgrades the candidate to an unverified,
non-blocking hypothesis.

The control catalogue maps applicable controls to NIST SSDF, OWASP ASVS 5.0,
and SLSA references. SARIF uses stable partial fingerprints so identical reruns
deduplicate.

## Safety Boundary

- Paths are repository-relative, canonicalized, and confined to the root.
- Absolute paths, traversal, symlinks, non-regular files, identity races, and
  over-limit inputs are rejected or recorded as incomplete.
- File count, bytes, time, findings, and output are bounded.
- Caller text containing recognized secret patterns is rejected; recognized
  provider and assignment formats are also redacted in depth. Callers must
  never submit raw values because arbitrary unlabelled strings cannot be
  classified perfectly.
- Arbitrary executables, shell strings, and inherited host secrets are
  forbidden. Default collection performs no network access; approved adapters
  receive fixed offline flags, which do not enforce a firewall.
- Curated analyzer execution, when supported, requires exact approval bound to
  adapter ID/version, revision, fingerprint, and policy digest.

Approved adapters execute trusted repository and toolchain code with the
current user's host privileges. Post-run fingerprints detect bound-tree
changes but do not police ignored files, `.git`, external paths, escaped
processes, or network effects. Untrusted code or any run requiring enforced
isolation requires a read-only container or VM with networking disabled. Node
launchers whose local toolchain identity cannot be attested are discovery-only
in this version.

## Suppression And Accepted Risk

A record must bind the exact finding fingerprint and scope and include owner,
reason, approval reference, creation date, expiry date, compensating control,
and residual risk. Blanket, expired, malformed, or source-stale records do not
suppress findings.
Expiry uses current server time, is bound into the receipt, and is checked again
before release readiness accepts that receipt.

## Compatibility

`jstack_security_audit` remains the bounded credential-pattern scanner used by
existing release readiness. Its output, receipt kind, and release behavior are
unchanged. Audit receipts are a separate kind and are required for release only
when `audit.releaseRequiresAuditReceipt` is explicitly enabled.

Artifact-only audits return an aggregate scope-manifest digest, file and byte
counts, coverage, and limitations. Per-file hashes remain internal to bounded
validation and are not returned by the public response. Artifact-only results
are advisory, issue no Git-bound receipt, and cannot claim JStack release
certification.

## Policy

Use `jstack.enterprise.json` for nested audit policy. Projects may strengthen
the defaults but cannot weaken these floors: read-only operation, no raw
secrets, no arbitrary execution, no network by default, exact execution
approval, complete evidence for pass, and owner/reason/expiry suppressions.
Policy `requiredDomains` are merged into every selected profile;
`reliability` maps to the combined `correctness` domain used by the result
contract.

## Standards References

- [NIST Secure Software Development Framework (SP 800-218)](https://csrc.nist.gov/pubs/sp/800/218/final)
- [OWASP Application Security Verification Standard 5.0](https://github.com/OWASP/ASVS/releases/tag/v5.0.0)
- [SLSA specification 1.2](https://slsa.dev/spec/v1.2/)
- [FIRST CVSS 4.0](https://www.first.org/cvss/v4-0/)
- [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

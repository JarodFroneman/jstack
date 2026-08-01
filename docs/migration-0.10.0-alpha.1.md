# Migrating To JStack v0.10.0-alpha.1

JStack v0.10.0-alpha.1 implements Stage 0 of the planned verified
security-remediation program inside the existing Audit mastery track. It is a
prerelease because Stages 1 through 9 of that new program are not yet shipped.
There is no new slash command, agent role, MCP tool, approval token, terminal
step, or expanded permission.

## What changes

- Audit Stage 0 is renamed from **Safe Audit Operator** to **Safe Security
  Operator**.
- The audit curriculum content version increases from 1 to 2 while retaining
  its existing schema and filename.
- Stage 0 adds `security-orientation.json` to the required artifact set.
- Advancement now requires two distinct inert independent labs:
  `a0-hostile-repository` and `a0-novel-vulnerability`.
- Both attempts must score at least 80 and pass an exact deterministic contract
  covering CIA, authorization, untrusted repository content, execution,
  disclosure, and non-authority boundaries.

## Safety boundary

The labs use synthetic inert local scenarios with training-only authorization.
They perform no repository execution, network access, secret access, exploit
development, public disclosure, remediation, Git change, deployment, or
production action. The only permitted writes are the four declared artifacts
under `.jstack-training/`.

Passing Stage 0 is orientation evidence only. It does not prove vulnerability
discovery or remediation competence and grants no repository execution,
remediation, publication, merge, release, deployment, or production authority.

## Existing mastery state

The local profile remains `jstack.mastery.profile.v3`; no profile migration is
required.

- Operators who already completed Audit Stage 0 retain their completed stage
  and attempt history.
- Operators currently at Audit Stage 0 must complete the new two-lab rule.
- Historical `a0-orientation` attempts remain in the history but do not satisfy
  the new advancement pair.
- Engineering and Loop mastery tracks are unchanged.

## Install and verify

Install the five plugins and shared MCP server from the same immutable
`v0.10.0-alpha.1` tag, then restart Codex or open a new task.

~~~bash
python3 scripts/sync_artifacts.py --check
python3 -m unittest discover -s tests -v
python3 mcp/jstack/smoke_test.py
python3 scripts/install.py
~~~

Verify that `jstack_runtime_status` reports `0.10.0-alpha.1`, the canonical tool
inventory remains 50, and the installed payload contains:

~~~text
~/.codex/mcp/jstack/schemas/audit-security-orientation.v1.schema.json
~~~

The MCP process mounted in an already-open task remains the prior version until
that task reconnects or Codex restarts.

## Rollback

Check out `v0.9.1`, rerun the transactional installer, restart Codex, and run
the installed smoke test. Preserve `~/.jstack/mastery/profile.json`; the older
runtime tolerates retained attempt metadata, but it will use the v0.9.1 Audit
Stage 0 curriculum while installed.

Rollback removes this deterministic Stage 0 gate. It does not undo or delete
any `.jstack-training/` artifacts automatically.

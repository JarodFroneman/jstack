# Stage 18 — Cross-Host Compatibility

## Status and authority

| Item | Value |
| --- | --- |
| Objective | Separate portable JStack methodologies from host runtime capabilities |
| Authority effect | None; a host contract describes support only |
| Advance gate | **PASS** — unsupported capabilities report unavailable or unsupported |
| Release state | Packaged in `v0.11.0`; this record grants no release, deployment, or installation authority |

`mcp/jstack/hosts/catalog.v1.json` is the closed release-tested host catalog.
`mcp/jstack/hosts/registry.py` turns it into a digest-bound contract before
Team Composer routing.

| Host | Support level | Important boundary |
| --- | --- | --- |
| Codex Desktop/CLI | Full | Commands, skills, MCP, subagents, Goal continuation, approvals, and local providers are release-tested; host-native browser control is not claimed |
| Claude Code | Preview | stdio MCP, approval UI, and local-process provider are described; no Codex packaging, bounded-subagent, or continuation parity is claimed |
| Generic MCP client | Protocol-only | stdio connectivity only; workflow/provider equivalence is not claimed |
| Unknown host | Unsupported | Requested known capabilities return `UNSUPPORTED`; nothing is emulated |

Methodology selection is host-neutral. Only capabilities marked `AVAILABLE`
may inform the physical execution topology. `UNAVAILABLE` means the known host
lacks a release-tested surface. `UNSUPPORTED` means JStack has no tested host
contract. MCP connectivity alone never implies full parity.

## Integration

`jstack_plan` and `jstack_team_plan` accept the additive optional `host_id`
for the current catalog and default compatible callers to `codex`. The Team
Plan result exposes `hostContract`; its digest and host ID are signed into the
Unified Team receipt and recomputed before dispatch. Unsupported or tampered
contracts cannot manufacture a host capability or authority.

The host contract sets `methodologyPortable: true`,
`executionAuthorized: false`, and `authorityEffect: none`. It cannot authorize
source edits, local processes, browser capture, Git, release, deployment, or
production actions.

Focused tests validate schemas, known/unknown hosts, no fake Claude/Codex
parity, unknown-capability rejection, tamper rejection, and identical
methodology selection across hosts.

The pinned gstack host/contributor sources informed the declarative capability
approach. JStack does not copy gstack host output, installers, prompts,
permissions, generated state, or runtime authority.

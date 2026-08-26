# Stage 14 — Solo, Professional, and Enterprise Profiles

## Status and authority

| Item | Value |
| --- | --- |
| Objective | Add explicit policy-driven governance profiles without changing execution authority |
| Default | Professional for compatible callers that omit the new field |
| Architecture | One Team Composer, one authority kernel, one monotonic risk-floor system |
| Advance gate | **PASS** — a lower profile cannot bypass a mandatory risk floor |
| Release state | Packaged in `v0.11.0`; this record grants no release, deployment, or installation authority |

The public planning inputs now distinguish `operating_profile` from command
mode, team topology, scope strategy, risk class, and the legacy
`quality_level`. This prevents “Solo” from being interpreted as weaker
security or “Enterprise” from being interpreted as permission for more
actions.

## Profile behavior

| Profile | Intended ceremony | Minimum governance behavior |
| --- | --- | --- |
| Solo | Proportional and low-friction | Smallest competent team and focused verification, subject to every risk floor |
| Professional | Balanced commercial delivery | Independent correctness review and QA where applicable |
| Enterprise | Strong separation and policy evidence | Professional controls plus policy conformance and risk-register evidence |

Profiles may increase evidence, independence, or ceremony. They cannot expand
the user's task mode, write scope, Git scope, provider authority, release
authority, or production authority. Authentication, security, destructive,
financial, production, and other classified work continues to resolve through
the same monotonic risk-floor policy. A Solo authentication request still
selects the mandatory security, identity/access, and QA expertise.

## Integration and compatibility

`mcp/jstack/orchestration/mode_integration.py` resolves the explicit profile
and defaults omitted values to Professional. `mcp/jstack/orchestration/
team_composer.py` applies the profile only after task classification and risk
floor resolution. `mcp/jstack/orchestration/policy.v1.json` remains the closed
source of profile controls.

The additive optional input appears on `jstack_plan` and `jstack_team_plan`.
Older callers retain the Professional default. Existing command names, legacy
quality levels, tool names, aliases, receipts, and provider boundaries remain
available. The profile ID and resulting delivery pipeline are bound into the
Unified Team receipt and verified before dynamic dispatch.

Focused tests prove profile independence from quality level, common authority
architecture, stronger Professional/Enterprise evidence, Solo risk-floor
preservation, and rejection of unsupported profile names.

No profile is a shortcut around Prompt Compilation, Context Readiness, Team
Plan scope, host permissions, external-action approval, or release readiness.

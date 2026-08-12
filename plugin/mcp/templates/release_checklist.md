# JStack Release Checklist

## Scope And Authority

- User request/reference:
- Explicitly requested external actions:
- Out-of-scope or prohibited actions:
- Provider / owner / repository / visibility:
- Remote name and URL:
- Branch / tag / full commit:
- Target environment:
- Release scope:
- Explicit comparison base:
- Protected-path approval/reference when applicable:
- Human security reviewer/reference:
- Policy digest:

JStack readiness, QA, security, audit, launch, and release receipts are
evidence, not action authority. Repository, provider, deployment, and
production actions remain limited to the user's explicit conversational scope
and the host/provider's normal permission controls. JStack does not require an
approval token, challenge digest, signing command, permit mailbox, or terminal
paste. If the target, action, visibility, or risk materially changes, stop and
obtain updated conversational direction before acting.

For an annotated release, record the exact commit, tag, branch, release target,
and resulting provider references. Do not infer merge, tag, publication, or
deployment authority from a passing evidence receipt.

## Preflight

- Policy check:
- Git status:
- Protected paths:
- Diff hygiene:
- Public-contract compatibility check:
- Product-boundary check:
- QA receipt for every discovered test/lint/typecheck/build command:
- Complete current-tree and release-history security receipt:
- Accountable launch profile owner/reference:
- Declared launch surfaces and target URL:
- Current passing launch receipt:
- Release-profile audit receipt when required by launch surfaces:
- Security/compliance review:

## Rollback

- Rollback owner:
- Rollback command or manual steps:
- Data backup or migration reversal:
- Time limit to rollback decision:

## Monitoring

- Health endpoint or smoke test:
- Logs/dashboard:
- Canary signal:
- Error budget or failure threshold:
- Post-release observation window:

## Handoff

- Files changed:
- Checks run:
- Open risks:
- Next follow-up:

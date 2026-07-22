# JStack Release Checklist

## Approval

- Readiness assessment request (not action authority):
- Named action approver:
- External approval reference:
- Exact protected action ID:
- Challenge digest:
- Authorization ID:
- Permit operation ID and expiry:
- Provider / owner / repository / visibility:
- Remote name and URL:
- Branch / tag / full commit:
- Push ref kind (branch-only or tag-only):
- Human security reviewer/reference:
- Target environment:
- Release scope:
- Explicit comparison base:
- HEAD commit:
- Policy digest:

Create and consume a fresh authorization for every separate repository
creation, remote add/change, commit, push, pull-request creation, merge, tag,
release, deployment, or production mutation. Never reuse this checklist entry
as authority for the next action.

For an annotated release tag, record and authorize local tag creation, exact
tag-only push, tag CI, and release creation as distinct steps.

## Preflight

- Policy check:
- Git status:
- Protected paths:
- Diff hygiene:
- QA receipt for every discovered test/lint/typecheck/build command:
- Complete current-tree and release-history security receipt:
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

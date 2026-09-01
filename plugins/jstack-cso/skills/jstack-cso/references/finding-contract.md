# CSO Finding Contract

Every reported finding must contain:

```text
Finding ID
Title
Severity
Confidence
Status
Phase and category
Affected component
Evidence
Attack precondition
Potential impact
Verified fact
Inference
Recommended remediation
Validation test
Residual risk
Relevant standard
Exploit scenario
Verification method
```

## Evidence Gate

Before promotion, quote the exact motivating source or artifact line using a
repository-relative path, line number, and SHA-256 digest. Redact any complete
secret. When a framework generates a symbol, cite the migration, schema,
descriptor, decorator, or metaclass that creates it.

If the motivating source cannot be cited, confidence is at most 5/10 and the
candidate stays outside the daily main report. A pattern match is not proof of
reachability, deployment, missing middleware, or exploitability.

## Status

- `VERIFIED`: confirmed by source tracing or separately authorized safe evidence.
- `UNVERIFIED`: plausible pattern whose full path or control boundary is missing.
- `TENTATIVE`: comprehensive-mode candidate below the daily confidence floor.

## Severity

Severity combines realistic attacker access, exploitability, blast radius, data
sensitivity, persistence, detectability, and business impact. Browser-readable
route names, ordinary UI logic, public identifiers, or missing best practices do
not become high severity without a concrete attack path.

## False-Positive Rules

- Respect framework-native protections and trace middleware/data-layer controls.
- Client authorization signals require server verification but are not alone a
  proven authorization vulnerability.
- Dynamic consumers prevent an automatic unused-response-property conclusion.
- Intentionally public identifiers are not secrets, but still need provider-side
  origin, quota, scope, and abuse controls.
- Test fixtures and documentation are excluded unless imported or deployed.
  `SKILL.md` is executable prompt policy and is not ordinary documentation.
- Missing generic controls are findings only when tied to a material surface and
  realistic impact.
- Do not report generic DoS, resource consumption, or logging gaps unless they
  create concrete authentication, AI-spend, export, extraction, or abuse risk.
- User content in a normal user-message position is not itself prompt injection.

## Secret Response

For a verified leaked secret, recommend revoke, rotate, remove from delivery,
scrub history where appropriate, determine the exposure window, inspect provider
audit logs, and add prevention. Never test the value or include it in the report.

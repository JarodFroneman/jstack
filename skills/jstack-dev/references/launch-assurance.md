# Launch Assurance

Use launch assurance for a clean, committed release candidate. It adds a
typed product-launch gate to QA, security, audit, rollback, and monitoring; it
does not replace any of them.

## Declare applicability

Call `jstack_launch_assess` with an explicit `base_ref`, target environment,
accountable profile owner, reference, and every applicable surface:

- `core`: always required.
- `public-web`: internet-reachable web, API, or documentation surface.
- `browser-ui`: browser-operated user interface.
- `authenticated`: login, authorization, entitlements, or paywall.
- `database`: application data stored or read from a database.
- `transactional-email`: account, billing, or other product email.
- `search-indexed`: public pages intended for search discovery.
- `performance-sensitive`: explicit latency or web-performance expectation.
- `analytics`: analytics events or product measurement.
- `payments`: monetary transaction or reconciliation behavior.
- `commercial`: customer, subscriber, or paid product.
- `tracking`: cookies, recordings, advertising, or non-essential tracking.
- `ai-paid-endpoints`: abuse can create material AI, vendor, or compute cost.
- `regulated-data`: personal, financial, health, or regulated data.

Do not omit a surface to avoid a control. JStack intentionally does not infer
the profile because inference can silently miss business and legal facts. A
production web-like target requires a bounded HTTPS URL without credentials,
query text, or a fragment.

## Collect typed evidence

For every selected blocker and required control, create a bounded evidence
artifact inside the Git project or `~/.jstack/evidence`, then call
`jstack_launch_evidence_register`. Use the control's permitted evidence kind
and one honest outcome: `pass`, `fail`, `incomplete`, or `not-applicable`.

JStack hashes the artifact, path identity, verifier, reference, and summary;
it does not return artifact content. Keep raw secrets, personal data, payment
data, mailbox credentials, full email bodies, session tokens, prompts, and
unredacted telemetry out of evidence. The named verifier remains accountable
for semantic truth. A hash proves which artifact was attested, not that the
artifact's claim is correct.

`not-applicable` is allowed only on controls whose catalog metadata permits it
and still requires current evidence. Changing the commit, policy, catalog,
surface declaration, environment, or target invalidates affected receipts.

## Finalize fail-closed

Call `jstack_launch_finalize` with exactly one current receipt per evidenced
control. Missing, failed, incomplete, malformed, stale, duplicate, or
contract-drifted blocker/required evidence prevents readiness. Missing or
failed advisory evidence remains a warning.

Blockers cannot be waived. A required control can be waived only when both the
catalog and policy allow it, and the record names an owner, reason, external
approval reference, expiry within 30 days, compensating control, and residual
risk. A waiver is a structured recorded decision, not an authenticated legal
or security certification.

## Consume at release readiness

Production `jstack_release_readiness` requires the current passing
`launchReceipt`. A profile containing `public-web`, `commercial`, `payments`,
or `regulated-data` also requires a current complete repository-wide
release-profile audit receipt by default. Projects may strengthen the policy
with additional required controls, shorter evidence age, more audit-triggering
surfaces, or disabled waivers.

Launch tools perform no web requests, payments, deployments, or production
mutations. Live payment, email, DNS, search-console, analytics, browser, legal,
and device checks are performed through separately authorized safe workflows;
JStack only registers their bounded evidence. A launch or release-readiness
receipt always has `executionAuthorized=false` and never authorizes commit,
push, pull request, merge, tag, release, deployment, or production mutation.

The 37-control v1 catalog adapts Nico Burkart's pre-launch checklist into
conditional JStack engineering controls. Source priorities are retained only
as provenance; JStack's gate levels and safety rules are independent judgments.

"""Deterministically build the JStack Launch Assurance v2 control catalogue."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
V1_CATALOG_PATH = ROOT / "catalog.v1.json"

RISK_TIERS = ("low", "medium", "high", "critical")
ARTIFACT_FORMATS = ("jstack-json", "sarif-2.1.0", "scanner-json")
EVIDENCE_KINDS = (
    "automated-test",
    "authorization-matrix",
    "browser-test",
    "code-review",
    "configuration-snapshot",
    "cost-control-report",
    "data-map",
    "datastore-probe",
    "delivery-test",
    "human-attestation",
    "http-security-report",
    "legal-document",
    "license-report",
    "manual-test",
    "monitoring-report",
    "penetration-test",
    "performance-report",
    "provider-receipt",
    "sbom",
    "security-scan",
)

SURFACES = (
    (
        "core",
        "Every production software change, including services without a public browser surface.",
        "low",
    ),
    (
        "public-web",
        "An internet-reachable website, application, API, or documentation surface.",
        "medium",
    ),
    (
        "browser-ui",
        "A user interface rendered and operated in a web browser.",
        "medium",
    ),
    (
        "authenticated",
        "A surface with login, authorization, entitlements, or paywall decisions.",
        "high",
    ),
    (
        "cookie-authenticated",
        "A browser surface that authenticates state-changing requests with cookies.",
        "high",
    ),
    (
        "database",
        "A change that stores or reads application data from a database.",
        "high",
    ),
    (
        "transactional-email",
        "A product that sends signup, account, billing, or other transactional email.",
        "medium",
    ),
    (
        "search-indexed",
        "A public surface intended to be discovered through search engines.",
        "low",
    ),
    (
        "performance-sensitive",
        "A user-facing surface with an explicit latency or web-performance expectation.",
        "medium",
    ),
    (
        "analytics",
        "A product that emits analytics events or product measurement data.",
        "medium",
    ),
    (
        "payments",
        "A product that initiates, receives, or reconciles monetary transactions.",
        "critical",
    ),
    (
        "commercial",
        "A product offered to customers, subscribers, or paying users.",
        "medium",
    ),
    (
        "tracking",
        "A product using cookies, recordings, advertising, or non-essential behavioral tracking.",
        "high",
    ),
    (
        "ai-paid-endpoints",
        "An endpoint whose abuse creates meaningful AI inference cost.",
        "high",
    ),
    (
        "regulated-data",
        "A product handling financial, health, identity, or otherwise regulated data.",
        "critical",
    ),
    (
        "public-form",
        "An unauthenticated or public workflow that accepts submitted user input.",
        "medium",
    ),
    (
        "cross-origin-api",
        "A browser-consumed API intended to accept requests from one or more other origins.",
        "high",
    ),
    (
        "untrusted-input",
        "A server, worker, import, upload, webhook, or tool boundary that consumes untrusted input.",
        "high",
    ),
    (
        "cost-bearing-endpoints",
        "An endpoint whose abuse creates material vendor, storage, compute, messaging, or operational cost.",
        "high",
    ),
    (
        "personal-data",
        "A product collecting or processing identifiable personal data.",
        "high",
    ),
    (
        "licensed-assets",
        "A product shipping third-party fonts, media, datasets, models, templates, or other licensed assets.",
        "medium",
    ),
    (
        "software-supply-chain",
        "A product built from third-party packages, containers, generated code, or vendored components.",
        "medium",
    ),
)


def _requirement(
    requirement_id: str,
    description: str,
    evidence_kinds: list[str],
    assertions: list[str],
    *,
    artifact_formats: list[str] | None = None,
    minimum_count: int = 1,
    minimum_distinct_producers: int = 1,
    minimum_observations: int = 1,
    independent: bool = False,
    machine_verifiable: bool = True,
    applies_at: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "id": requirement_id,
        "description": description,
        "evidenceKinds": evidence_kinds,
        "artifactFormats": artifact_formats or ["jstack-json"],
        "minimumCount": minimum_count,
        "minimumDistinctProducers": minimum_distinct_producers,
        "minimumObservations": minimum_observations,
        "independent": independent,
        "machineVerifiable": machine_verifiable,
        "requiredAssertions": assertions,
        "appliesAtRiskTiers": applies_at or list(RISK_TIERS),
    }


SPECIAL_REQUIREMENTS: dict[str, list[dict[str, Any]]] = {
    "security-database-row-access": [
        _requirement(
            "effective-policy-snapshot",
            "Capture the effective datastore authorization policy and every privileged bypass boundary.",
            ["configuration-snapshot"],
            ["row-policy-enforced", "privileged-bypass-documented"],
        ),
        _requirement(
            "cross-tenant-probe-matrix",
            "Exercise anonymous and cross-tenant read and write attempts against protected records.",
            ["datastore-probe", "automated-test"],
            [
                "anonymous-read-denied",
                "anonymous-write-denied",
                "cross-tenant-read-denied",
                "cross-tenant-write-denied",
            ],
            minimum_observations=4,
        ),
    ],
    "security-server-side-authz": [
        _requirement(
            "authorization-decision-matrix",
            "Exercise protected operations as unauthenticated, wrong-role, expired-session, and forged-entitlement principals.",
            ["authorization-matrix", "automated-test"],
            [
                "unauthenticated-denied",
                "wrong-role-denied",
                "expired-session-denied",
                "entitlement-server-enforced",
            ],
            minimum_observations=4,
        )
    ],
    "security-environment-route-exposure": [
        _requirement(
            "public-exposure-probes",
            "Probe environment, backup, debug, source-map, and diagnostic paths without retaining sensitive response bodies.",
            ["http-security-report", "security-scan"],
            [
                "environment-routes-denied",
                "debug-routes-disabled",
                "backup-artifacts-unreachable",
                "source-maps-secret-free",
            ],
            minimum_observations=4,
        )
    ],
    "security-client-secret-exposure": [
        _requirement(
            "secret-egress-scan",
            "Scan client bundles, source maps, public configuration, logs, traces, and model context for privileged secrets.",
            ["security-scan"],
            [
                "client-bundle-scan-complete",
                "source-map-scan-complete",
                "log-and-trace-scan-complete",
                "model-context-scan-complete",
                "privileged-secret-findings-resolved",
            ],
            minimum_observations=5,
        )
    ],
    "security-https-enforcement": [
        _requirement(
            "transport-verification",
            "Verify the deployed certificate, redirect behavior, mixed content, and transport policy.",
            ["http-security-report", "provider-receipt"],
            [
                "certificate-valid",
                "http-redirect-safe",
                "mixed-active-content-absent",
                "transport-policy-enforced",
            ],
            minimum_observations=4,
        )
    ],
    "security-expensive-endpoint-rate-limits": [
        _requirement(
            "abuse-limit-tests",
            "Exercise burst, sustained, concurrency, payload, and trivial-identity bypass limits before the costly dependency.",
            ["automated-test", "cost-control-report"],
            [
                "burst-limit-enforced",
                "sustained-limit-enforced",
                "identity-bypass-denied",
                "payload-and-concurrency-bounded",
                "rejected-before-cost",
            ],
            minimum_observations=5,
        )
    ],
    "security-server-input-validation": [
        _requirement(
            "untrusted-boundary-tests",
            "Exercise malformed, oversized, injected, encoded, and type-confused inputs at authoritative server boundaries.",
            ["automated-test", "security-scan"],
            [
                "allowlist-validation-enforced",
                "parameterized-data-access",
                "contextual-output-encoding",
                "payload-and-upload-limits-enforced",
            ],
            minimum_observations=4,
        )
    ],
    "security-error-data-minimization": [
        _requirement(
            "error-and-output-leak-tests",
            "Exercise public failures and inspect bounded response, log, trace, and telemetry classifications.",
            ["automated-test", "http-security-report"],
            [
                "public-errors-nondiagnostic",
                "account-enumeration-resistant",
                "api-responses-data-minimized",
                "logs-and-telemetry-secret-free",
                "correlation-identifiers-safe",
            ],
            minimum_observations=5,
        )
    ],
    "security-auth-failure-matrix": [
        _requirement(
            "authentication-failure-matrix",
            "Exercise wrong, absent, expired, reused, duplicated, throttled, recovery, and session-expiry paths.",
            ["authorization-matrix", "automated-test"],
            [
                "nonexistent-user-response-equivalent",
                "repeated-failure-throttled",
                "expired-link-denied",
                "reused-link-denied",
                "duplicate-signup-safe",
                "recovery-path-tested",
                "session-expiry-enforced",
            ],
            minimum_observations=7,
        )
    ],
    "security-response-headers": [
        _requirement(
            "deployed-header-verification",
            "Inspect deployed browser security headers and cookie attributes on representative routes.",
            ["http-security-report"],
            [
                "content-security-policy-enforced-or-owned-exception",
                "frame-embedding-restricted",
                "hsts-enforced",
                "content-type-sniffing-disabled",
                "referrer-policy-bounded",
                "permissions-policy-bounded",
                "secure-cookie-attributes-enforced",
            ],
            minimum_observations=7,
        )
    ],
    "security-cors-policy": [
        _requirement(
            "cors-negative-matrix",
            "Exercise trusted, untrusted, null, credentialed, and preflight origin cases.",
            ["automated-test", "http-security-report"],
            [
                "trusted-origins-explicit",
                "untrusted-origin-denied",
                "null-origin-denied-or-owned",
                "credential-wildcard-absent",
                "preflight-policy-enforced",
                "vary-origin-correct",
            ],
            minimum_observations=6,
        )
    ],
    "security-csrf-protection": [
        _requirement(
            "csrf-negative-tests",
            "Exercise cross-site state changes independently of CORS behavior.",
            ["automated-test", "browser-test"],
            [
                "cross-site-state-change-denied",
                "csrf-token-or-origin-check-enforced",
                "samesite-cookie-policy-reviewed",
                "unsafe-methods-protected",
            ],
            minimum_observations=4,
        )
    ],
    "security-cost-abuse-controls": [
        _requirement(
            "cost-boundary-inventory",
            "Inventory cost-bearing operations and prove identity, tenant, payload, concurrency, and provider ceilings.",
            ["configuration-snapshot", "cost-control-report"],
            [
                "cost-bearing-operations-inventoried",
                "per-identity-or-tenant-quotas-enforced",
                "payload-and-concurrency-ceilings-enforced",
                "provider-hard-cap-or-equivalent-enforced",
            ],
            minimum_observations=4,
        ),
        _requirement(
            "cost-operations-response",
            "Prove owned spend alerts, anomaly detection, and a tested emergency disable path.",
            ["monitoring-report", "cost-control-report"],
            [
                "spend-alert-owned-and-delivered",
                "cost-anomaly-alert-owned-and-delivered",
                "emergency-kill-switch-tested",
            ],
            minimum_observations=3,
            minimum_distinct_producers=1,
        ),
    ],
    "security-final-independent-scan": [
        _requirement(
            "independent-security-scan",
            "Import a complete, target-bound independent security scan in normalized SARIF or bounded JSON.",
            ["security-scan"],
            [
                "scan-complete",
                "scope-covered",
                "target-bound",
                "no-unresolved-critical",
                "no-unresolved-high",
            ],
            artifact_formats=["sarif-2.1.0", "scanner-json"],
            independent=True,
            minimum_observations=1,
            applies_at=["high", "critical"],
        ),
        _requirement(
            "critical-human-security-review",
            "Record an independent human or penetration-test review for a critical launch.",
            ["manual-test", "penetration-test"],
            ["critical-human-review-complete", "critical-residual-risk-owned"],
            independent=True,
            machine_verifiable=False,
            minimum_observations=2,
            applies_at=["critical"],
        ),
    ],
    "analytics-bot-protection": [
        _requirement(
            "proportionate-abuse-tests",
            "Exercise the server-side abuse boundary selected for public forms and automation-prone flows.",
            ["automated-test", "security-scan"],
            [
                "server-side-abuse-control-enforced",
                "challenge-token-server-validated-if-used",
                "challenge-replay-denied-if-used",
                "accessible-fallback-owned",
            ],
            minimum_observations=4,
        )
    ],
    "legal-data-governance-map": [
        _requirement(
            "implementation-data-map",
            "Map collected data to systems, processors, regions, transfers, retention, deletion, export, and backups.",
            ["data-map"],
            [
                "data-categories-mapped",
                "systems-and-processors-mapped",
                "storage-regions-and-transfers-mapped",
                "retention-and-deletion-mapped",
                "export-and-rights-paths-mapped",
                "backup-lifecycle-mapped",
            ],
            minimum_observations=6,
        ),
        _requirement(
            "accountable-data-decision",
            "Record the accountable owner and jurisdiction-dependent decision used to evaluate the implemented data map.",
            ["human-attestation", "legal-document"],
            ["accountable-owner-recorded", "legal-scope-and-jurisdictions-recorded"],
            machine_verifiable=False,
            minimum_observations=2,
        ),
    ],
    "legal-license-provenance": [
        _requirement(
            "software-bill-of-materials",
            "Produce a complete component and asset inventory bound to the release candidate.",
            ["sbom"],
            [
                "direct-components-inventoried",
                "transitive-components-inventoried",
                "assets-data-models-inventoried",
            ],
            minimum_observations=3,
        ),
        _requirement(
            "license-disposition",
            "Evaluate commercial-use, attribution, copyleft, unknown-license, and generated-source provenance.",
            ["license-report"],
            [
                "license-identities-resolved",
                "commercial-use-reviewed",
                "attribution-obligations-recorded",
                "copyleft-obligations-dispositioned",
                "unknown-licenses-dispositioned",
            ],
            minimum_observations=5,
        ),
    ],
    "final-hostile-form-input": [
        _requirement(
            "hostile-input-regression",
            "Exercise hostile browser and API inputs and verify authoritative rejection, safe encoding, and redacted failures.",
            ["automated-test", "browser-test", "security-scan"],
            [
                "hostile-input-rejected",
                "stored-and-reflected-output-encoded",
                "injection-payloads-contained",
                "failure-output-redacted",
            ],
            minimum_observations=4,
        )
    ],
}


def _generic_requirements(control: dict[str, Any]) -> list[dict[str, Any]]:
    kinds = list(control["evidenceKinds"])
    non_machine = set(kinds).issubset(
        {"human-attestation", "legal-document", "manual-test", "code-review"}
    )
    return [
        _requirement(
            "primary-verification",
            "Provide structured evidence for the complete control objective and every named verification method.",
            kinds,
            [f"{control['id']}-verified"],
            machine_verifiable=not non_machine,
        )
    ]


def _new_control(
    control_id: str,
    category: str,
    title: str,
    objective: str,
    priority: str,
    gate: str,
    applicability: dict[str, list[str]],
    owner: str,
    safety: str,
    *,
    waivable: bool = False,
    allow_not_applicable: bool = False,
    minimum_risk_tier: str = "low",
) -> dict[str, Any]:
    requirements = SPECIAL_REQUIREMENTS[control_id]
    kinds = sorted(
        {
            kind
            for requirement in requirements
            for kind in requirement["evidenceKinds"]
        },
        key=EVIDENCE_KINDS.index,
    )
    return {
        "id": control_id,
        "sequence": 0,
        "category": category,
        "title": title,
        "objective": objective,
        "sourcePriority": priority,
        "gateLevel": gate,
        "minimumRiskTier": minimum_risk_tier,
        "applicability": applicability,
        "evidenceKinds": kinds,
        "evidenceRequirements": requirements,
        "verificationMethods": [requirement["description"] for requirement in requirements],
        "maxAgeMinutes": 1440,
        "ownerRole": owner,
        "waivable": waivable,
        "allowNotApplicable": allow_not_applicable,
        "safetyNotes": safety,
    }


def _security_additions() -> list[dict[str, Any]]:
    return [
        _new_control(
            "security-server-input-validation",
            "security",
            "Validate untrusted input at authoritative server boundaries",
            "Prove that malformed, oversized, injected, and type-confused input is rejected or safely encoded before it reaches privileged operations.",
            "blocker",
            "blocker",
            {"allOf": ["core"], "anyOf": ["untrusted-input", "public-form", "cross-origin-api"]},
            "security",
            "Generic sanitization claims are insufficient; evidence must distinguish validation, parameterization, output encoding, and intentional HTML sanitization.",
        ),
        _new_control(
            "security-error-data-minimization",
            "security",
            "Prevent public errors, APIs, logs, and telemetry from leaking sensitive data",
            "Prove that failure paths resist account enumeration and expose only the minimum data needed by the caller and operator.",
            "blocker",
            "blocker",
            {"allOf": ["core"], "anyOf": ["public-web", "authenticated", "cross-origin-api", "ai-paid-endpoints"]},
            "security",
            "Retained evidence must classify leaks without copying secrets, tokens, personal data, or raw production payloads.",
        ),
        _new_control(
            "security-auth-failure-matrix",
            "security",
            "Exercise authentication, verification, recovery, and session failure states",
            "Prove safe behavior for nonexistent users, repeated failures, expired or reused links, duplicate signup, recovery, and session expiry.",
            "blocker",
            "blocker",
            {"allOf": ["authenticated"], "anyOf": []},
            "security",
            "Fixed lockout counts are not universal; controls must resist enumeration and denial-of-service while preserving owned recovery.",
        ),
        _new_control(
            "security-response-headers",
            "security",
            "Verify deployed browser security headers and cookie attributes",
            "Prove that the deployed response policy constrains script, framing, transport, sniffing, referrer, browser capabilities, and authentication cookies.",
            "first-week",
            "required",
            {"allOf": ["public-web"], "anyOf": []},
            "security",
            "A missing header may require an owned, evidence-backed exception; copying a generic header set without compatibility testing is not a pass.",
            waivable=True,
        ),
        _new_control(
            "security-cors-policy",
            "security",
            "Verify cross-origin API policy with negative tests",
            "Prove that only intended browser origins receive the configured cross-origin access and credential behavior.",
            "blocker",
            "blocker",
            {"allOf": ["cross-origin-api"], "anyOf": []},
            "security",
            "CORS is not authentication or CSRF protection and cannot satisfy either control.",
        ),
        _new_control(
            "security-csrf-protection",
            "security",
            "Protect cookie-authenticated state changes from cross-site requests",
            "Prove that unsafe state-changing browser requests require an effective CSRF boundary independent of CORS.",
            "blocker",
            "blocker",
            {"allOf": ["cookie-authenticated"], "anyOf": []},
            "security",
            "Use framework protections or validated tokens, Origin or Fetch Metadata checks, and appropriate SameSite policy for the actual architecture.",
        ),
        _new_control(
            "security-cost-abuse-controls",
            "security",
            "Bound spend, resource consumption, and emergency exposure",
            "Prove inventory, quotas, provider ceilings, alerts, anomaly response, and an owned kill switch for materially cost-bearing operations.",
            "blocker",
            "blocker",
            {"allOf": ["core"], "anyOf": ["cost-bearing-endpoints", "ai-paid-endpoints"]},
            "security",
            "Rate limiting alone cannot satisfy this control; limits must reflect endpoint cost, tenant, payload, concurrency, and downstream provider behavior.",
        ),
        _new_control(
            "security-final-independent-scan",
            "security",
            "Import independent final security evidence",
            "Require normalized, complete, target-bound independent scanner evidence at high risk and an additional independent human review at critical risk.",
            "blocker",
            "blocker",
            {"allOf": ["core"], "anyOf": []},
            "security",
            "Untriaged scanner output does not automatically prove failure or safety; unresolved high or critical findings, stale scope, truncation, and target mismatch fail closed.",
            minimum_risk_tier="high",
        ),
    ]


def _legal_additions() -> list[dict[str, Any]]:
    return [
        _new_control(
            "legal-data-governance-map",
            "legal",
            "Reconcile implemented data flows with accountable privacy decisions",
            "Map collected data, systems, processors, regions, transfers, retention, deletion, export, and backups, then bind the map to an accountable jurisdictional decision.",
            "blocker",
            "blocker",
            {"allOf": ["core"], "anyOf": ["personal-data", "regulated-data", "tracking"]},
            "legal-owner",
            "JStack validates evidence coordination and implementation alignment; it does not provide legal advice or certify compliance.",
        ),
        _new_control(
            "legal-license-provenance",
            "legal",
            "Verify software, asset, data, model, and generated-source provenance",
            "Produce an SBOM and owned license disposition for direct and transitive components, assets, datasets, models, and generated or copied source.",
            "blocker",
            "blocker",
            {"allOf": ["core"], "anyOf": ["licensed-assets", "software-supply-chain", "commercial"]},
            "legal-owner",
            "License obligations are fact-specific; JStack must not convert GPL, AI authorship, or commercial-use questions into blanket conclusions.",
        ),
    ]


def _upgrade_control(control: dict[str, Any]) -> dict[str, Any]:
    upgraded = json.loads(json.dumps(control))
    control_id = str(upgraded["id"])
    upgraded["minimumRiskTier"] = "low"
    if control_id == "security-expensive-endpoint-rate-limits":
        upgraded["applicability"] = {
            "allOf": ["core"],
            "anyOf": ["ai-paid-endpoints", "cost-bearing-endpoints"],
        }
    elif control_id == "analytics-bot-protection":
        upgraded["applicability"] = {
            "allOf": ["core"],
            "anyOf": ["public-web", "authenticated", "public-form"],
        }
    elif control_id == "legal-terms-privacy":
        upgraded["applicability"]["anyOf"] = [
            "public-web",
            "commercial",
            "analytics",
            "tracking",
            "personal-data",
            "regulated-data",
        ]
    elif control_id == "final-hostile-form-input":
        upgraded["applicability"] = {
            "allOf": ["core"],
            "anyOf": ["browser-ui", "public-form", "cross-origin-api", "untrusted-input"],
        }
    requirements = SPECIAL_REQUIREMENTS.get(control_id) or _generic_requirements(upgraded)
    upgraded["evidenceRequirements"] = requirements
    upgraded["evidenceKinds"] = sorted(
        {
            kind
            for requirement in requirements
            for kind in requirement["evidenceKinds"]
        },
        key=EVIDENCE_KINDS.index,
    )
    return upgraded


def build_catalog() -> dict[str, Any]:
    """Return the deterministic v2 catalogue derived from the retained v1 source."""
    v1 = json.loads(V1_CATALOG_PATH.read_text(encoding="utf-8"))
    controls = [_upgrade_control(control) for control in v1["controls"]]
    security = [control for control in controls if control["category"] == "security"]
    email = [control for control in controls if control["category"] == "email"]
    findability = [control for control in controls if control["category"] == "findability"]
    speed = [control for control in controls if control["category"] == "speed"]
    analytics = [control for control in controls if control["category"] == "analytics"]
    legal = [control for control in controls if control["category"] == "legal"]
    final_test = [control for control in controls if control["category"] == "final-test"]
    ordered = [
        *security,
        *_security_additions(),
        *email,
        *findability,
        *speed,
        *analytics,
        *legal,
        *_legal_additions(),
        *final_test,
    ]
    for sequence, control in enumerate(ordered, 1):
        control["sequence"] = sequence
    return {
        "schemaVersion": "jstack.launch.controls.v2",
        "catalogVersion": "2.0.0",
        "sourceProvenance": {
            "sources": [
                {
                    "sourceUrl": v1["sourceProvenance"]["sourceUrl"],
                    "reviewedAt": v1["sourceProvenance"]["reviewedAt"],
                    "purpose": "Original 37-point launch checklist adapted in JStack v0.8.",
                },
                {
                    "sourceUrl": "https://x.com/PrajwalTomar_/status/2080974596392837123",
                    "reviewedAt": "2026-07-26",
                    "purpose": "Security, cost, data-governance, and scanner gap analysis for Launch Assurance v2.",
                },
            ],
            "adaptationNotice": (
                "JStack converts source checklist concerns into provider-neutral, "
                "risk-tiered engineering controls. Product names, fixed thresholds, "
                "legal generalizations, and unsupported guarantees are not copied as policy."
            ),
        },
        "surfaces": [
            {"id": surface_id, "description": description, "riskFloor": risk_floor}
            for surface_id, description, risk_floor in SURFACES
        ],
        "riskTiers": list(RISK_TIERS),
        "riskModel": {
            "highSecurityControlsAreBlockers": True,
            "criticalRequiredControlsAreBlockers": True,
            "criticalWaiversAllowed": False,
            "independentScannerMinimumTier": "high",
            "criticalHumanReviewRequired": True,
        },
        "statuses": ["pass", "fail", "incomplete", "not-applicable", "waived"],
        "evidenceKinds": list(EVIDENCE_KINDS),
        "artifactFormats": list(ARTIFACT_FORMATS),
        "controls": ordered,
    }

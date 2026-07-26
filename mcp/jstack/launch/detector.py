"""Bounded, content-minimized surface hint detection for Launch Assurance v2."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable


_RULES: dict[str, tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]] = {
    "public-web": (
        (
            ("web-framework-path", r"(^|/)(app|pages|public|routes?|www)(/|$)"),
            ("web-manifest", r"(^|/)package\.json$"),
        ),
        (
            ("web-framework", r"\b(next|nuxt|remix|express|fastapi|flask|django|rails)\b"),
            ("http-route", r"\b(GET|POST|PUT|PATCH|DELETE)\s+/(?!/)"),
        ),
    ),
    "browser-ui": (
        (
            ("frontend-source", r"\.(tsx|jsx|vue|svelte|html)$"),
            ("frontend-directory", r"(^|/)(components?|pages?|views?|frontend|client)(/|$)"),
        ),
        (
            ("browser-dom", r"\b(document|window|localStorage|sessionStorage)\b"),
            ("frontend-library", r"\b(react|vue|svelte|angular)\b"),
        ),
    ),
    "authenticated": (
        (
            ("auth-path", r"(^|/)(auth|login|sessions?|oauth|identity)(/|[._-])"),
        ),
        (
            ("auth-library", r"\b(next-auth|authjs|passport|oauth2?|openid|oidc|jsonwebtoken|jwt)\b"),
            ("authorization-decision", r"\b(authori[sz]e|permission|rbac|entitlement)\b"),
        ),
    ),
    "cookie-authenticated": (
        (
            ("session-path", r"(^|/)(session|cookie|auth)(/|[._-])"),
        ),
        (
            ("cookie-session", r"\b(session[_-]?cookie|httpOnly|sameSite|set-cookie)\b"),
            ("csrf-marker", r"\b(csrf|xsrf)\b"),
        ),
    ),
    "database": (
        (
            ("database-schema", r"(^|/)(migrations?|schema|prisma|database|db)(/|[._-])"),
            ("database-file", r"\.(sql|prisma)$"),
        ),
        (
            ("database-library", r"\b(supabase|prisma|sqlalchemy|sequelize|typeorm|postgres|mysql|sqlite)\b"),
            ("database-query", r"\b(SELECT|INSERT|UPDATE|DELETE)\b.+\b(FROM|INTO|SET)\b"),
        ),
    ),
    "transactional-email": (
        (
            ("email-template", r"(^|/)(emails?|mail|templates?)(/|[._-])"),
        ),
        (
            ("email-provider", r"\b(sendgrid|postmark|mailgun|resend|ses|nodemailer)\b"),
            ("transactional-email", r"\b(send(mail|email)|verification email|password reset)\b"),
        ),
    ),
    "analytics": (
        (
            ("analytics-path", r"(^|/)(analytics|telemetry|events?)(/|[._-])"),
        ),
        (
            ("analytics-provider", r"\b(posthog|mixpanel|segment|amplitude|google analytics|gtag)\b"),
            ("analytics-event", r"\b(track|capture|identify)\s*\("),
        ),
    ),
    "tracking": (
        (
            ("tracking-path", r"(^|/)(tracking|cookies?|consent)(/|[._-])"),
        ),
        (
            ("tracking-provider", r"\b(hotjar|fullstory|clarity|pixel|session recording)\b"),
            ("nonessential-cookie", r"\b(cookie consent|tracking consent|advertising cookie)\b"),
        ),
    ),
    "payments": (
        (
            ("payment-path", r"(^|/)(payments?|billing|checkout|subscriptions?|webhooks?)(/|[._-])"),
        ),
        (
            ("payment-provider", r"\b(stripe|paypal|adyen|braintree|paddle)\b"),
            ("payment-operation", r"\b(payment intent|checkout session|refund|invoice)\b"),
        ),
    ),
    "ai-paid-endpoints": (
        (
            ("ai-path", r"(^|/)(ai|llm|agents?|models?|prompts?)(/|[._-])"),
        ),
        (
            ("ai-provider", r"\b(openai|anthropic|bedrock|gemini|vertex ai|mistral)\b"),
            ("model-inference", r"\b(chat completions?|responses api|generate content|inference)\b"),
        ),
    ),
    "cost-bearing-endpoints": (
        (
            ("cost-path", r"(^|/)(jobs?|workers?|uploads?|exports?|render|transcode)(/|[._-])"),
        ),
        (
            ("billable-provider", r"\b(openai|anthropic|twilio|sendgrid|cloudinary|mapbox)\b"),
            ("resource-operation", r"\b(transcode|render|export|bulk import|background job)\b"),
        ),
    ),
    "public-form": (
        (
            ("form-source", r"(^|/)(forms?|contact|signup|register)(/|[._-])"),
        ),
        (
            ("html-form", r"<form\b"),
            ("form-data", r"\b(FormData|multipart/form-data)\b"),
        ),
    ),
    "cross-origin-api": (
        (
            ("cors-config", r"(^|/)(cors|cross-origin)(/|[._-])"),
        ),
        (
            ("cors-library", r"\b(cors|CORSMiddleware)\b"),
            ("cors-header", r"\bAccess-Control-Allow-Origin\b"),
        ),
    ),
    "untrusted-input": (
        (
            ("input-boundary", r"(^|/)(uploads?|imports?|webhooks?|api|routes?)(/|[._-])"),
        ),
        (
            ("request-input", r"\b(req\.(body|query|params)|request\.(json|form)|multipart)\b"),
            ("webhook-input", r"\b(webhook|callback payload|message handler)\b"),
        ),
    ),
    "personal-data": (
        (
            ("privacy-path", r"(^|/)(privacy|personal-data|data-protection|gdpr)(/|[._-])"),
        ),
        (
            ("personal-data-model", r"\b(date_of_birth|postal_address|phone_number|personal_data)\b"),
            ("privacy-rights", r"\b(data subject|right to erasure|data deletion|data export)\b"),
        ),
    ),
    "regulated-data": (
        (
            ("regulated-path", r"(^|/)(kyc|aml|health|medical|financial|compliance)(/|[._-])"),
        ),
        (
            ("regulated-marker", r"\b(hipaa|pci[- ]?dss|kyc|aml|medical record|tax id|national id)\b"),
        ),
    ),
    "licensed-assets": (
        (
            ("licensed-asset", r"\.(woff2?|ttf|otf|mp3|mp4|mov|glb|gltf|fbx|obj|psd|ai)$"),
            ("asset-directory", r"(^|/)(assets?|fonts?|media|models?|datasets?)(/|$)"),
        ),
        (
            ("asset-license", r"\b(creative commons|commercial license|attribution required|royalty[- ]free)\b"),
        ),
    ),
    "software-supply-chain": (
        (
            ("dependency-manifest", r"(^|/)(package(-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|go\.mod|go\.sum|Cargo\.(toml|lock))$"),
            ("container-manifest", r"(^|/)(Dockerfile|compose\.ya?ml)$"),
        ),
        (
            ("vendored-source", r"\b(vendored|third[- ]party component|generated source)\b"),
        ),
    ),
}


def detect_surface_hints(
    documents: Iterable[tuple[str, str]],
) -> list[dict[str, object]]:
    """Return content-free path/marker hints; source text is never returned."""
    files_by_surface: dict[str, set[str]] = defaultdict(set)
    markers_by_surface: dict[str, set[str]] = defaultdict(set)
    path_and_content: dict[str, set[str]] = defaultdict(set)
    for path, text in documents:
        normalized_path = path.replace("\\", "/")
        for surface, (path_rules, content_rules) in _RULES.items():
            path_hits = {
                marker
                for marker, pattern in path_rules
                if re.search(pattern, normalized_path, re.IGNORECASE)
            }
            content_hits = {
                marker
                for marker, pattern in content_rules
                if re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            }
            if not path_hits and not content_hits:
                continue
            files_by_surface[surface].add(normalized_path)
            markers_by_surface[surface].update(path_hits | content_hits)
            if path_hits and content_hits:
                path_and_content[surface].add(normalized_path)
    hints: list[dict[str, object]] = []
    for surface in _RULES:
        files = sorted(files_by_surface.get(surface, set()))
        markers = sorted(markers_by_surface.get(surface, set()))
        if not files or not markers:
            continue
        high = bool(path_and_content.get(surface)) or len(markers) >= 2
        hints.append(
            {
                "surface": surface,
                "confidence": "high" if high else "medium",
                "matchedFiles": files[:20],
                "markers": markers[:20],
            }
        )
    return hints

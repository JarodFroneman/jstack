"""Bounded Product/Design decisions under the Product Interface authority plane."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable, Optional


DESIGN_DECISION_INPUT_SCHEMA_VERSION = "jstack.ui.design-decision-input.v1"
DESIGN_DECISION_SCHEMA_VERSION = "jstack.ui.design-decision.v1"
DESIGN_POLICY_SCHEMA_VERSION = "jstack.ui.design-policy.v1"
DESIGN_POLICY_VERSION = "1.0.0"

DESIGN_PRECEDENCE = (
    "explicit-user-requirements",
    "existing-application-design-system",
    "existing-tokens-and-components",
    "existing-accessibility-requirements",
    "approved-evidence-reference-bundle",
    "selected-product-domain-guidance",
    "fallback-jstack-design-guidance",
)
DESIGN_CAPABILITY_IDS = (
    "product-discovery",
    "product-challenge",
    "design-consultation",
    "design-analysis",
    "design-review",
    "design-alternatives",
    "ux-analysis",
    "design-systems",
    "accessibility",
    "dx-review",
    "ui-implementation-guidance",
)
DESIGN_MODES = ("preserve-and-extend", "directed", "exploration")
FINDING_DISPOSITIONS = ("fact", "recommendation", "assumption", "unknown")
SOURCE_KINDS = (
    "explicit-user",
    "verified-repository",
    "jstack-policy",
    "approved-reference-bundle",
    "verified-external",
    "product-domain-guidance",
    "disclosed-inference",
)
SELECTION_SOURCES = ("active-conversation", "approved-reference-bundle")
SYSTEM_DISPOSITIONS = ("not-applicable", "preserve", "extend", "replace")

MAX_FINDINGS = 32
MAX_ALTERNATIVES = 3
MAX_SOURCE_REFERENCES = 64
MAX_CONTEXT_ITEMS = 12
MAX_REQUIREMENT_ITEMS = 16

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z][a-z0-9._-]{1,79}$")

_INPUT_FIELDS = {
    "schemaVersion",
    "mode",
    "capabilities",
    "productContext",
    "findings",
    "alternatives",
    "selection",
    "existingSystemDisposition",
    "explicitNonGoals",
    "sourceReferences",
}
_OUTPUT_FIELDS = _INPUT_FIELDS | {"policy", "authority", "decisionSha256"}
_AUTHORITY = {
    "authorityEffect": "none",
    "implementationAuthorized": False,
    "candidateMutationAuthorized": False,
    "productionMutationAuthorized": False,
    "providerInvocationAuthorized": False,
}


class DesignDecisionError(ValueError):
    """A Product/Design decision is invalid or exceeds its authority."""


def _copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True))


def _canonical_digest(value: Any) -> str:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _text(
    value: Any,
    field: str,
    *,
    minimum: int = 1,
    maximum: int = 2_000,
) -> str:
    if not isinstance(value, str):
        raise DesignDecisionError(f"{field} must be a string.")
    normalized = value.strip()
    if not minimum <= len(normalized) <= maximum:
        raise DesignDecisionError(
            f"{field} must contain {minimum} to {maximum} characters."
        )
    if any(ord(character) < 32 and character not in "\t\n" for character in normalized):
        raise DesignDecisionError(f"{field} contains unsupported control characters.")
    return normalized


def _identifier(value: Any, field: str) -> str:
    normalized = _text(value, field, maximum=80)
    if ID_RE.fullmatch(normalized) is None:
        raise DesignDecisionError(f"{field} must be a portable lowercase identifier.")
    return normalized


def _sha256(value: Any, field: str) -> str:
    normalized = _text(value, field, maximum=64)
    if SHA256_RE.fullmatch(normalized) is None:
        raise DesignDecisionError(f"{field} must be a lowercase SHA-256 digest.")
    return normalized


def _strings(
    value: Any,
    field: str,
    *,
    minimum: int = 0,
    maximum: int = MAX_REQUIREMENT_ITEMS,
    allowed: Optional[Iterable[str]] = None,
    item_maximum: int = 1_000,
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise DesignDecisionError(
            f"{field} must contain {minimum} to {maximum} strings."
        )
    normalized = [
        _text(item, f"{field}[{index}]", maximum=item_maximum)
        for index, item in enumerate(value)
    ]
    if len(normalized) != len(set(normalized)):
        raise DesignDecisionError(f"{field} must not contain duplicates.")
    if allowed is not None:
        unknown = sorted(set(normalized) - set(allowed))
        if unknown:
            raise DesignDecisionError(
                f"{field} contains unsupported values: {', '.join(unknown)}"
            )
    return normalized


def design_policy() -> dict[str, Any]:
    """Return the immutable Stage 10 Product/Design policy."""
    return {
        "schemaVersion": DESIGN_POLICY_SCHEMA_VERSION,
        "version": DESIGN_POLICY_VERSION,
        "precedence": list(DESIGN_PRECEDENCE),
        "capabilities": list(DESIGN_CAPABILITY_IDS),
        "limits": {
            "maximumAlternatives": MAX_ALTERNATIVES,
            "maximumFindings": MAX_FINDINGS,
            "maximumSourceReferences": MAX_SOURCE_REFERENCES,
        },
        "invariants": {
            "humanSelectionRequired": True,
            "secondDesignAuthorityAllowed": False,
            "rawApprovalStored": False,
            "rawPromptStored": False,
            "rawSourceContentStored": False,
            "secretsStored": False,
            "hiddenReasoningStored": False,
            "automaticCandidateMutationAllowed": False,
            "automaticProductionMutationAllowed": False,
        },
    }


def _policy_binding() -> dict[str, Any]:
    policy = design_policy()
    return {
        "schemaVersion": policy["schemaVersion"],
        "version": policy["version"],
        "sha256": _canonical_digest(policy),
    }


def _product_context(value: Any) -> dict[str, Any]:
    expected = {"targetUsers", "primaryJobs", "desiredOutcomes"}
    if not isinstance(value, dict) or set(value) != expected:
        raise DesignDecisionError(
            "productContext must contain exactly targetUsers, primaryJobs, and desiredOutcomes."
        )
    return {
        "targetUsers": _strings(
            value["targetUsers"],
            "productContext.targetUsers",
            minimum=1,
            maximum=MAX_CONTEXT_ITEMS,
        ),
        "primaryJobs": _strings(
            value["primaryJobs"],
            "productContext.primaryJobs",
            minimum=1,
            maximum=MAX_CONTEXT_ITEMS,
        ),
        "desiredOutcomes": _strings(
            value["desiredOutcomes"],
            "productContext.desiredOutcomes",
            minimum=1,
            maximum=MAX_CONTEXT_ITEMS,
        ),
    }


def _source_references(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_SOURCE_REFERENCES:
        raise DesignDecisionError(
            f"sourceReferences must contain one to {MAX_SOURCE_REFERENCES} records."
        )
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(value):
        if not isinstance(row, dict) or set(row) != {"id", "kind", "sha256"}:
            raise DesignDecisionError(
                f"sourceReferences[{index}] must contain exactly id, kind, and sha256."
            )
        source_id = _identifier(row["id"], f"sourceReferences[{index}].id")
        if source_id in seen:
            raise DesignDecisionError("sourceReferences ids must be unique.")
        seen.add(source_id)
        kind = _text(row["kind"], f"sourceReferences[{index}].kind", maximum=80)
        if kind not in SOURCE_KINDS:
            raise DesignDecisionError(
                f"sourceReferences[{index}].kind is unsupported."
            )
        result.append(
            {
                "id": source_id,
                "kind": kind,
                "sha256": _sha256(
                    row["sha256"], f"sourceReferences[{index}].sha256"
                ),
            }
        )
    return sorted(result, key=lambda item: item["id"])


def _reference_ids(
    value: Any,
    field: str,
    *,
    known: set[str],
) -> list[str]:
    result = _strings(
        value,
        field,
        minimum=1,
        maximum=MAX_SOURCE_REFERENCES,
        item_maximum=80,
    )
    for item in result:
        _identifier(item, field)
    unknown = sorted(set(result) - known)
    if unknown:
        raise DesignDecisionError(
            f"{field} references unknown source ids: {', '.join(unknown)}"
        )
    return result


def _findings(
    value: Any,
    *,
    capabilities: set[str],
    source_ids: set[str],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 0 <= len(value) <= MAX_FINDINGS:
        raise DesignDecisionError(
            f"findings must contain zero to {MAX_FINDINGS} records."
        )
    expected = {
        "id",
        "capabilityId",
        "disposition",
        "statement",
        "sourceReferenceIds",
    }
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(value):
        if not isinstance(row, dict) or set(row) != expected:
            raise DesignDecisionError(f"findings[{index}] has an unsupported field set.")
        finding_id = _identifier(row["id"], f"findings[{index}].id")
        if finding_id in seen:
            raise DesignDecisionError("finding ids must be unique.")
        seen.add(finding_id)
        capability = _text(
            row["capabilityId"], f"findings[{index}].capabilityId", maximum=80
        )
        if capability not in capabilities:
            raise DesignDecisionError(
                f"findings[{index}].capabilityId was not selected in capabilities."
            )
        disposition = _text(
            row["disposition"], f"findings[{index}].disposition", maximum=40
        )
        if disposition not in FINDING_DISPOSITIONS:
            raise DesignDecisionError(f"findings[{index}].disposition is unsupported.")
        result.append(
            {
                "id": finding_id,
                "capabilityId": capability,
                "disposition": disposition,
                "statement": _text(
                    row["statement"], f"findings[{index}].statement", maximum=2_000
                ),
                "sourceReferenceIds": _reference_ids(
                    row["sourceReferenceIds"],
                    f"findings[{index}].sourceReferenceIds",
                    known=source_ids,
                ),
            }
        )
    return result


def _alternatives(
    value: Any,
    *,
    source_ids: set[str],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ALTERNATIVES:
        raise DesignDecisionError(
            f"alternatives must contain one to {MAX_ALTERNATIVES} records."
        )
    expected = {
        "id",
        "title",
        "summary",
        "productRationale",
        "hierarchy",
        "userFlow",
        "designSystemStrategy",
        "visualDirection",
        "interactionModel",
        "responsiveStrategy",
        "accessibilityRequirements",
        "stateRequirements",
        "tradeoffs",
        "implementationGuidance",
        "sourceReferenceIds",
    }
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, row in enumerate(value):
        if not isinstance(row, dict) or set(row) != expected:
            raise DesignDecisionError(
                f"alternatives[{index}] has an unsupported field set."
            )
        alternative_id = _identifier(row["id"], f"alternatives[{index}].id")
        if alternative_id in seen:
            raise DesignDecisionError("alternative ids must be unique.")
        seen.add(alternative_id)
        result.append(
            {
                "id": alternative_id,
                "title": _text(
                    row["title"], f"alternatives[{index}].title", maximum=160
                ),
                "summary": _text(
                    row["summary"], f"alternatives[{index}].summary", maximum=1_000
                ),
                "productRationale": _text(
                    row["productRationale"],
                    f"alternatives[{index}].productRationale",
                    maximum=1_500,
                ),
                "hierarchy": _text(
                    row["hierarchy"], f"alternatives[{index}].hierarchy", maximum=1_500
                ),
                "userFlow": _text(
                    row["userFlow"], f"alternatives[{index}].userFlow", maximum=1_500
                ),
                "designSystemStrategy": _text(
                    row["designSystemStrategy"],
                    f"alternatives[{index}].designSystemStrategy",
                    maximum=1_500,
                ),
                "visualDirection": _text(
                    row["visualDirection"],
                    f"alternatives[{index}].visualDirection",
                    maximum=1_500,
                ),
                "interactionModel": _text(
                    row["interactionModel"],
                    f"alternatives[{index}].interactionModel",
                    maximum=1_500,
                ),
                "responsiveStrategy": _text(
                    row["responsiveStrategy"],
                    f"alternatives[{index}].responsiveStrategy",
                    maximum=1_500,
                ),
                "accessibilityRequirements": _strings(
                    row["accessibilityRequirements"],
                    f"alternatives[{index}].accessibilityRequirements",
                    minimum=1,
                ),
                "stateRequirements": _strings(
                    row["stateRequirements"],
                    f"alternatives[{index}].stateRequirements",
                    minimum=1,
                ),
                "tradeoffs": _strings(
                    row["tradeoffs"],
                    f"alternatives[{index}].tradeoffs",
                    minimum=1,
                ),
                "implementationGuidance": _strings(
                    row["implementationGuidance"],
                    f"alternatives[{index}].implementationGuidance",
                    minimum=1,
                ),
                "sourceReferenceIds": _reference_ids(
                    row["sourceReferenceIds"],
                    f"alternatives[{index}].sourceReferenceIds",
                    known=source_ids,
                ),
            }
        )
    return result


def _selection(
    value: Any,
    *,
    alternative_ids: set[str],
    allow_raw_approval: bool,
) -> dict[str, Any]:
    expected = {
        "alternativeId",
        "source",
        "approvalReference",
        "approvalSha256",
        "referencePrototypeId",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise DesignDecisionError(
            "selection must contain exactly alternativeId, source, approvalReference, approvalSha256, and referencePrototypeId."
        )
    alternative_id = _identifier(value["alternativeId"], "selection.alternativeId")
    if alternative_id not in alternative_ids:
        raise DesignDecisionError("selection.alternativeId does not name an alternative.")
    source = _text(value["source"], "selection.source", maximum=80)
    if source not in SELECTION_SOURCES:
        raise DesignDecisionError("selection.source is unsupported.")
    raw_reference = value["approvalReference"]
    raw_digest = value["approvalSha256"]
    prototype = value["referencePrototypeId"]
    if source == "active-conversation":
        if prototype is not None:
            raise DesignDecisionError(
                "active-conversation selection must not name a reference prototype."
            )
        if raw_reference is not None:
            if not allow_raw_approval:
                raise DesignDecisionError(
                    "Normalized design decisions must not retain the raw approval reference."
                )
            approval_reference = _text(
                raw_reference, "selection.approvalReference", maximum=1_000
            )
            approval_digest = hashlib.sha256(
                approval_reference.encode("utf-8")
            ).hexdigest()
            if raw_digest is not None and _sha256(
                raw_digest, "selection.approvalSha256"
            ) != approval_digest:
                raise DesignDecisionError(
                    "selection approval reference digest does not match."
                )
        elif raw_digest is not None:
            approval_digest = _sha256(raw_digest, "selection.approvalSha256")
        else:
            raise DesignDecisionError(
                "active-conversation selection requires an accountable approval reference or its SHA-256 digest."
            )
        prototype_id = None
    else:
        if raw_reference is not None or raw_digest is not None:
            raise DesignDecisionError(
                "reference-bundle selection must use its signed prototype binding, not an approval string."
            )
        approval_digest = None
        prototype_id = _identifier(
            prototype, "selection.referencePrototypeId"
        )
    return {
        "alternativeId": alternative_id,
        "source": source,
        "approvalReference": None,
        "approvalSha256": approval_digest,
        "referencePrototypeId": prototype_id,
    }


def _normalize_common(value: dict[str, Any], *, allow_raw_approval: bool) -> dict[str, Any]:
    mode = _text(value["mode"], "mode", maximum=40)
    if mode not in DESIGN_MODES:
        raise DesignDecisionError("mode is unsupported.")
    capabilities = _strings(
        value["capabilities"],
        "capabilities",
        minimum=1,
        maximum=len(DESIGN_CAPABILITY_IDS),
        allowed=DESIGN_CAPABILITY_IDS,
        item_maximum=80,
    )
    capabilities = [item for item in DESIGN_CAPABILITY_IDS if item in capabilities]
    source_references = _source_references(value["sourceReferences"])
    source_ids = {item["id"] for item in source_references}
    alternatives = _alternatives(value["alternatives"], source_ids=source_ids)
    selection = _selection(
        value["selection"],
        alternative_ids={item["id"] for item in alternatives},
        allow_raw_approval=allow_raw_approval,
    )
    disposition = _text(
        value["existingSystemDisposition"],
        "existingSystemDisposition",
        maximum=40,
    )
    if disposition not in SYSTEM_DISPOSITIONS:
        raise DesignDecisionError("existingSystemDisposition is unsupported.")
    return {
        "schemaVersion": DESIGN_DECISION_SCHEMA_VERSION,
        "mode": mode,
        "capabilities": capabilities,
        "productContext": _product_context(value["productContext"]),
        "findings": _findings(
            value["findings"],
            capabilities=set(capabilities),
            source_ids=source_ids,
        ),
        "alternatives": alternatives,
        "selection": selection,
        "existingSystemDisposition": disposition,
        "explicitNonGoals": _strings(
            value["explicitNonGoals"],
            "explicitNonGoals",
            maximum=MAX_REQUIREMENT_ITEMS,
        ),
        "sourceReferences": source_references,
    }


def _validate_context(
    decision: dict[str, Any],
    *,
    reference_bundle: Optional[dict[str, Any]],
    existing_system_present: bool,
    redesign_approved: bool,
) -> None:
    if not isinstance(existing_system_present, bool) or not isinstance(
        redesign_approved, bool
    ):
        raise DesignDecisionError("Design-decision context flags must be boolean.")
    alternatives = decision["alternatives"]
    mode = decision["mode"]
    if mode == "exploration":
        if not 2 <= len(alternatives) <= MAX_ALTERNATIVES:
            raise DesignDecisionError(
                "exploration mode requires two or three bounded alternatives."
            )
        if "design-alternatives" not in decision["capabilities"]:
            raise DesignDecisionError(
                "exploration mode requires the design-alternatives capability."
            )
    elif len(alternatives) != 1:
        raise DesignDecisionError(
            "preserve-and-extend and directed modes require exactly one design direction."
        )

    disposition = decision["existingSystemDisposition"]
    if existing_system_present:
        if disposition == "not-applicable":
            raise DesignDecisionError(
                "An established design system requires preserve, extend, or replace disposition."
            )
        if disposition == "replace" and not redesign_approved:
            raise DesignDecisionError(
                "Replacing an established design system requires separate accountable redesign approval."
            )
        if mode == "preserve-and-extend" and disposition == "replace":
            raise DesignDecisionError(
                "preserve-and-extend mode cannot replace the established design system."
            )
    elif disposition != "not-applicable":
        raise DesignDecisionError(
            "A project without an established design system must use not-applicable disposition."
        )

    kinds_by_id = {
        item["id"]: item["kind"] for item in decision["sourceReferences"]
    }
    if "explicit-user" not in set(kinds_by_id.values()):
        raise DesignDecisionError(
            "A design decision requires an explicit-user source reference."
        )
    for index, alternative in enumerate(alternatives):
        kinds = {kinds_by_id[item] for item in alternative["sourceReferenceIds"]}
        if "explicit-user" not in kinds:
            raise DesignDecisionError(
                f"alternatives[{index}] must trace to explicit user requirements."
            )

    selected = next(
        item
        for item in alternatives
        if item["id"] == decision["selection"]["alternativeId"]
    )
    selected_kinds = {
        kinds_by_id[item] for item in selected["sourceReferenceIds"]
    }
    if existing_system_present and "verified-repository" not in selected_kinds:
        raise DesignDecisionError(
            "The selected direction must trace to verified repository evidence when an established design system exists."
        )

    has_reference_source = "approved-reference-bundle" in set(kinds_by_id.values())
    if reference_bundle is None:
        if has_reference_source:
            raise DesignDecisionError(
                "approved-reference-bundle sources require a signed reference bundle bound into this UI contract."
            )
        if decision["selection"]["source"] == "approved-reference-bundle":
            raise DesignDecisionError(
                "Reference-bundle selection requires a signed reference bundle."
            )
        return

    if "approved-reference-bundle" not in selected_kinds:
        raise DesignDecisionError(
            "A bound reference bundle must be traceable from the selected design direction."
        )
    if decision["selection"]["source"] == "approved-reference-bundle":
        selected_prototype = reference_bundle.get("selectedPrototypeId")
        if selected_prototype is None:
            raise DesignDecisionError(
                "The signed reference bundle does not contain a human-selected prototype."
            )
        if decision["selection"]["referencePrototypeId"] != selected_prototype:
            raise DesignDecisionError(
                "The design selection does not match the signed reference bundle prototype."
            )


def build_design_decision(
    value: Any,
    *,
    reference_bundle: Optional[dict[str, Any]],
    existing_system_present: bool,
    redesign_approved: bool,
) -> dict[str, Any]:
    """Normalize and bind one human-selected Product/Design direction."""
    if not isinstance(value, dict):
        raise DesignDecisionError("designDecision must be an object.")
    if value.get("schemaVersion") == DESIGN_DECISION_SCHEMA_VERSION:
        decision = validate_design_decision(value)
        _validate_context(
            decision,
            reference_bundle=reference_bundle,
            existing_system_present=existing_system_present,
            redesign_approved=redesign_approved,
        )
        return decision
    if set(value) != _INPUT_FIELDS:
        raise DesignDecisionError(
            "Product/Design input must contain the exact v1 field set."
        )
    if value.get("schemaVersion") != DESIGN_DECISION_INPUT_SCHEMA_VERSION:
        raise DesignDecisionError(
            f"designDecision.schemaVersion must be {DESIGN_DECISION_INPUT_SCHEMA_VERSION}."
        )
    common = _normalize_common(value, allow_raw_approval=True)
    decision = {
        **common,
        "policy": _policy_binding(),
        "authority": _copy(_AUTHORITY),
    }
    _validate_context(
        decision,
        reference_bundle=reference_bundle,
        existing_system_present=existing_system_present,
        redesign_approved=redesign_approved,
    )
    decision["decisionSha256"] = _canonical_digest(decision)
    return decision


def validate_design_decision(value: Any) -> dict[str, Any]:
    """Validate the closed, normalized decision stored in a UI contract."""
    if not isinstance(value, dict) or set(value) != _OUTPUT_FIELDS:
        raise DesignDecisionError(
            "Normalized Product/Design decision has an unsupported field set."
        )
    if value.get("schemaVersion") != DESIGN_DECISION_SCHEMA_VERSION:
        raise DesignDecisionError(
            f"schemaVersion must be {DESIGN_DECISION_SCHEMA_VERSION}."
        )
    supplied_digest = _sha256(value.get("decisionSha256"), "decisionSha256")
    body = {key: child for key, child in value.items() if key != "decisionSha256"}
    if supplied_digest != _canonical_digest(body):
        raise DesignDecisionError("Product/Design decision digest does not match.")
    if value.get("policy") != _policy_binding():
        raise DesignDecisionError("Product/Design policy binding is stale or invalid.")
    if value.get("authority") != _AUTHORITY:
        raise DesignDecisionError("Product/Design authority invariants were weakened.")
    common_input = {
        key: value[key]
        for key in _INPUT_FIELDS
    }
    common_input["schemaVersion"] = DESIGN_DECISION_INPUT_SCHEMA_VERSION
    normalized = _normalize_common(common_input, allow_raw_approval=False)
    for field in _INPUT_FIELDS - {"schemaVersion"}:
        if value[field] != normalized[field]:
            raise DesignDecisionError(
                f"Product/Design decision field is not normalized: {field}"
            )
    return _copy(value)


__all__ = [
    "DESIGN_CAPABILITY_IDS",
    "DESIGN_DECISION_INPUT_SCHEMA_VERSION",
    "DESIGN_DECISION_SCHEMA_VERSION",
    "DESIGN_MODES",
    "DESIGN_POLICY_SCHEMA_VERSION",
    "DESIGN_POLICY_VERSION",
    "DESIGN_PRECEDENCE",
    "DesignDecisionError",
    "build_design_decision",
    "design_policy",
    "validate_design_decision",
]

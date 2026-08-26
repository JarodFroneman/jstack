"""Validate JStack departments and logical specialists without granting authority."""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

try:
    from .. import capabilities as capability_core
    from ..capabilities import registry as capability_registry
except (ImportError, ValueError):  # Installed MCP modules may be top-level.
    import capabilities as capability_core  # type: ignore[no-redef]
    from capabilities import registry as capability_registry  # type: ignore[no-redef]


DIRECTORY_SCHEMA_VERSION = "jstack.organization.directory.v1"
DIRECTORY_VERSION = "1.0.0"
DEFAULT_DIRECTORY_PATH = Path(__file__).with_name("directory.v1.json")
IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RISK_CLASSES = frozenset({"trivial", "normal", "elevated", "high", "production"})
CLASSIFICATIONS = capability_registry.CLASSIFICATION_IDS
MIN_SPECIALISTS = 25
MAX_SPECIALISTS = 35
MAX_DEPARTMENTS = 16
MAX_CAPABILITIES_PER_SPECIALIST = 4

TOP_LEVEL_FIELDS = {
    "schemaVersion",
    "directoryVersion",
    "capabilityCatalog",
    "sourceProvenance",
    "departments",
    "specialists",
    "invariants",
}
DEPARTMENT_FIELDS = {
    "id",
    "displayName",
    "purpose",
    "specialistIds",
    "selectionPolicy",
    "authorityEffect",
    "physicalAgentEffect",
}
SPECIALIST_FIELDS = {
    "id",
    "displayName",
    "description",
    "departmentId",
    "canonicalRoleId",
    "capabilityIds",
    "activation",
    "riskRequirements",
    "independence",
    "providerRequirementIds",
    "sourceProvenanceIds",
    "physicalAgentBinding",
    "authorityMode",
    "permissionOverridesAllowed",
}
FORBIDDEN_SPECIALIST_AUTHORITY_FIELDS = frozenset(
    {
        "mayEdit",
        "permissions",
        "permission",
        "sourceWrite",
        "gitWrite",
        "deploy",
        "productionApproval",
        "externalAction",
        "toolAccess",
    }
)


class OrganizationDirectoryError(ValueError):
    """A department or specialist violates the JStack organization contract."""


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _require_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise OrganizationDirectoryError(f"{field} must be an object.")
    return value


def _exact_fields(value: dict[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        raise OrganizationDirectoryError(
            f"{field} has invalid fields; "
            f"missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}."
        )


def _text(value: Any, field: str, *, max_chars: int = 2000) -> str:
    if not isinstance(value, str) or not value or len(value) > max_chars:
        raise OrganizationDirectoryError(
            f"{field} must be non-empty text of at most {max_chars} characters."
        )
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise OrganizationDirectoryError(f"{field} must be normalized printable text.")
    return value


def _identifier(value: Any, field: str) -> str:
    result = _text(value, field, max_chars=100)
    if IDENTIFIER_RE.fullmatch(result) is None:
        raise OrganizationDirectoryError(f"{field} must be a kebab-case identifier.")
    return result


def _sha256(value: Any, field: str) -> str:
    result = _text(value, field, max_chars=64)
    if SHA256_RE.fullmatch(result) is None:
        raise OrganizationDirectoryError(f"{field} must be a lowercase SHA-256 digest.")
    return result


def _list(
    value: Any,
    field: str,
    *,
    allow_empty: bool = False,
    max_items: int = 128,
    identifiers: bool = False,
    sorted_values: bool = False,
) -> list[str]:
    if not isinstance(value, list) or len(value) > max_items:
        raise OrganizationDirectoryError(f"{field} must be a bounded array.")
    if not allow_empty and not value:
        raise OrganizationDirectoryError(f"{field} must not be empty.")
    output = [
        _identifier(item, f"{field}[{index}]")
        if identifiers
        else _text(item, f"{field}[{index}]", max_chars=500)
        for index, item in enumerate(value)
    ]
    if len(output) != len(set(output)):
        raise OrganizationDirectoryError(f"{field} must not contain duplicates.")
    if sorted_values and output != sorted(output):
        raise OrganizationDirectoryError(f"{field} must be sorted.")
    return output


def _validate_capability_binding(value: Any) -> dict[str, Any]:
    binding = _require_object(value, "capabilityCatalog")
    _exact_fields(
        binding,
        {"schemaVersion", "catalogVersion", "catalogDigest"},
        "capabilityCatalog",
    )
    catalog = capability_core.load_catalog()
    expected = {
        "schemaVersion": catalog["schemaVersion"],
        "catalogVersion": catalog["catalogVersion"],
        "catalogDigest": capability_core.catalog_digest(catalog),
    }
    if binding != expected:
        raise OrganizationDirectoryError(
            "capabilityCatalog is stale relative to the canonical capability catalog."
        )
    return catalog


def _validate_provenance(value: Any) -> set[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise OrganizationDirectoryError("sourceProvenance must contain 1 to 16 records.")
    expected_fields = {
        "id",
        "sourceType",
        "sourceReference",
        "sourceDigest",
        "license",
        "adaptationClass",
        "copiedPromptContent",
    }
    ids: list[str] = []
    for index, raw in enumerate(value):
        field = f"sourceProvenance[{index}]"
        record = _require_object(raw, field)
        _exact_fields(record, expected_fields, field)
        ids.append(_identifier(record["id"], f"{field}.id"))
        if record["sourceType"] not in {"jstack-specification", "external-research"}:
            raise OrganizationDirectoryError(f"{field}.sourceType is invalid.")
        _text(record["sourceReference"], f"{field}.sourceReference", max_chars=1000)
        _sha256(record["sourceDigest"], f"{field}.sourceDigest")
        _text(record["license"], f"{field}.license", max_chars=100)
        if record["adaptationClass"] not in {"NATIVE", "ADAPTED"}:
            raise OrganizationDirectoryError(f"{field}.adaptationClass is invalid.")
        if record["copiedPromptContent"] is not False:
            raise OrganizationDirectoryError(
                f"{field}.copiedPromptContent must remain false."
            )
    if ids != sorted(set(ids)):
        raise OrganizationDirectoryError("sourceProvenance ids must be unique and sorted.")
    return set(ids)


def _validate_department(raw: Any, index: int) -> dict[str, Any]:
    field = f"departments[{index}]"
    department = _require_object(raw, field)
    _exact_fields(department, DEPARTMENT_FIELDS, field)
    _identifier(department["id"], f"{field}.id")
    _text(department["displayName"], f"{field}.displayName", max_chars=160)
    _text(department["purpose"], f"{field}.purpose", max_chars=1000)
    _list(
        department["specialistIds"],
        f"{field}.specialistIds",
        max_items=MAX_SPECIALISTS,
        identifiers=True,
        sorted_values=True,
    )
    if department["selectionPolicy"] != "dynamic-material-need":
        raise OrganizationDirectoryError(f"{field}.selectionPolicy is invalid.")
    if department["authorityEffect"] != "none":
        raise OrganizationDirectoryError(f"{field} cannot grant authority.")
    if department["physicalAgentEffect"] != "none":
        raise OrganizationDirectoryError(f"{field} cannot create a physical agent.")
    return department


def _validate_specialist(
    raw: Any,
    index: int,
    *,
    catalog: dict[str, Any],
    provenance_ids: set[str],
) -> dict[str, Any]:
    field = f"specialists[{index}]"
    specialist = _require_object(raw, field)
    if set(specialist) & FORBIDDEN_SPECIALIST_AUTHORITY_FIELDS:
        raise OrganizationDirectoryError(f"{field} contains an authority field.")
    _exact_fields(specialist, SPECIALIST_FIELDS, field)
    _identifier(specialist["id"], f"{field}.id")
    _text(specialist["displayName"], f"{field}.displayName", max_chars=160)
    _text(specialist["description"], f"{field}.description", max_chars=1000)
    _identifier(specialist["departmentId"], f"{field}.departmentId")
    role = _identifier(specialist["canonicalRoleId"], f"{field}.canonicalRoleId")
    if role not in capability_core.ROSTER_ROLE_IDS:
        raise OrganizationDirectoryError(f"{field}.canonicalRoleId is unknown.")
    capability_ids = _list(
        specialist["capabilityIds"],
        f"{field}.capabilityIds",
        max_items=MAX_CAPABILITIES_PER_SPECIALIST,
        identifiers=True,
        sorted_values=True,
    )
    try:
        capability_core.validate_role_capabilities(
            role,
            capability_ids,
            catalog=catalog,
        )
    except capability_core.CapabilityError as exc:
        raise OrganizationDirectoryError(f"{field} has invalid capabilities: {exc}") from exc

    activation = _require_object(specialist["activation"], f"{field}.activation")
    _exact_fields(
        activation,
        {"domains", "classifications", "changedSurfaces", "taskSignals"},
        f"{field}.activation",
    )
    _list(
        activation["domains"],
        f"{field}.activation.domains",
        max_items=16,
        identifiers=True,
        sorted_values=True,
    )
    classifications = _list(
        activation["classifications"],
        f"{field}.activation.classifications",
        max_items=len(CLASSIFICATIONS),
        sorted_values=True,
    )
    unknown_classifications = set(classifications) - set(CLASSIFICATIONS)
    if unknown_classifications:
        raise OrganizationDirectoryError(
            f"{field}.activation.classifications contains unknown values: "
            + ", ".join(sorted(unknown_classifications))
        )
    _list(
        activation["changedSurfaces"],
        f"{field}.activation.changedSurfaces",
        max_items=24,
        identifiers=True,
        sorted_values=True,
    )
    _list(
        activation["taskSignals"],
        f"{field}.activation.taskSignals",
        max_items=24,
    )

    risks = _require_object(specialist["riskRequirements"], f"{field}.riskRequirements")
    _exact_fields(risks, {"mandatoryFor", "prohibitedFor"}, f"{field}.riskRequirements")
    mandatory = _list(
        risks["mandatoryFor"],
        f"{field}.riskRequirements.mandatoryFor",
        allow_empty=True,
        max_items=len(RISK_CLASSES),
        identifiers=True,
    )
    prohibited = _list(
        risks["prohibitedFor"],
        f"{field}.riskRequirements.prohibitedFor",
        allow_empty=True,
        max_items=len(RISK_CLASSES),
        identifiers=True,
    )
    if (set(mandatory) | set(prohibited)) - RISK_CLASSES:
        raise OrganizationDirectoryError(f"{field}.riskRequirements contains unknown risk.")
    if set(mandatory) & set(prohibited):
        raise OrganizationDirectoryError(f"{field}.riskRequirements contradicts itself.")

    independence = _require_object(specialist["independence"], f"{field}.independence")
    _exact_fields(
        independence,
        {"requiredFor", "mustBeIndependentFromRoles"},
        f"{field}.independence",
    )
    _list(
        independence["requiredFor"],
        f"{field}.independence.requiredFor",
        allow_empty=True,
        max_items=16,
        identifiers=True,
        sorted_values=True,
    )
    independent_roles = _list(
        independence["mustBeIndependentFromRoles"],
        f"{field}.independence.mustBeIndependentFromRoles",
        allow_empty=True,
        max_items=len(capability_core.ROSTER_ROLE_IDS),
        identifiers=True,
        sorted_values=True,
    )
    if set(independent_roles) - capability_core.ROSTER_ROLE_IDS:
        raise OrganizationDirectoryError(f"{field}.independence contains unknown role.")

    _list(
        specialist["providerRequirementIds"],
        f"{field}.providerRequirementIds",
        allow_empty=True,
        max_items=16,
        identifiers=True,
        sorted_values=True,
    )
    source_ids = _list(
        specialist["sourceProvenanceIds"],
        f"{field}.sourceProvenanceIds",
        max_items=8,
        identifiers=True,
        sorted_values=True,
    )
    if set(source_ids) - provenance_ids:
        raise OrganizationDirectoryError(f"{field} references unknown provenance.")
    if specialist["physicalAgentBinding"] != "composer-assigned":
        raise OrganizationDirectoryError(f"{field} cannot bind its own physical agent.")
    if specialist["authorityMode"] != "inherit-canonical-role":
        raise OrganizationDirectoryError(f"{field} cannot define authority.")
    if specialist["permissionOverridesAllowed"] is not False:
        raise OrganizationDirectoryError(f"{field} cannot override role permission.")
    return specialist


def validate_directory(value: Any) -> dict[str, Any]:
    directory = _require_object(value, "directory")
    _exact_fields(directory, TOP_LEVEL_FIELDS, "directory")
    if directory["schemaVersion"] != DIRECTORY_SCHEMA_VERSION:
        raise OrganizationDirectoryError("Unsupported directory schemaVersion.")
    version = _text(directory["directoryVersion"], "directoryVersion", max_chars=64)
    if version != DIRECTORY_VERSION or SEMVER_RE.fullmatch(version) is None:
        raise OrganizationDirectoryError("Unsupported directoryVersion.")
    catalog = _validate_capability_binding(directory["capabilityCatalog"])
    provenance_ids = _validate_provenance(directory["sourceProvenance"])

    raw_departments = directory["departments"]
    if not isinstance(raw_departments, list) or not 1 <= len(raw_departments) <= MAX_DEPARTMENTS:
        raise OrganizationDirectoryError(
            f"departments must contain 1 to {MAX_DEPARTMENTS} records."
        )
    departments = [
        _validate_department(raw, index) for index, raw in enumerate(raw_departments)
    ]
    department_ids = [department["id"] for department in departments]
    if department_ids != sorted(set(department_ids)):
        raise OrganizationDirectoryError("department ids must be unique and sorted.")

    raw_specialists = directory["specialists"]
    if not isinstance(raw_specialists, list) or not MIN_SPECIALISTS <= len(raw_specialists) <= MAX_SPECIALISTS:
        raise OrganizationDirectoryError(
            f"specialists must contain {MIN_SPECIALISTS} to {MAX_SPECIALISTS} records."
        )
    specialists = [
        _validate_specialist(
            raw,
            index,
            catalog=catalog,
            provenance_ids=provenance_ids,
        )
        for index, raw in enumerate(raw_specialists)
    ]
    specialist_ids = [specialist["id"] for specialist in specialists]
    if specialist_ids != sorted(set(specialist_ids)):
        raise OrganizationDirectoryError("specialist ids must be unique and sorted.")

    department_membership: dict[str, str] = {}
    for department in departments:
        for specialist_id in department["specialistIds"]:
            if specialist_id in department_membership:
                raise OrganizationDirectoryError(
                    f"Specialist appears in multiple departments: {specialist_id}"
                )
            department_membership[specialist_id] = department["id"]
    if set(department_membership) != set(specialist_ids):
        raise OrganizationDirectoryError(
            "Department membership must cover every specialist exactly once."
        )
    for specialist in specialists:
        if department_membership[specialist["id"]] != specialist["departmentId"]:
            raise OrganizationDirectoryError(
                f"Specialist department mismatch: {specialist['id']}"
            )

    represented_roles = {specialist["canonicalRoleId"] for specialist in specialists}
    if represented_roles != capability_core.ROSTER_ROLE_IDS:
        raise OrganizationDirectoryError(
            "The directory must represent every existing canonical JStack role."
        )

    invariants = _require_object(directory["invariants"], "invariants")
    _exact_fields(
        invariants,
        {
            "specialistIsPhysicalAgent",
            "roleIsPersona",
            "capabilityGrantsPermission",
            "providerGrantsAuthority",
            "evidenceGrantsAuthorization",
            "permissionSource",
            "physicalAgentAssignmentSource",
        },
        "invariants",
    )
    for field in (
        "specialistIsPhysicalAgent",
        "roleIsPersona",
        "capabilityGrantsPermission",
        "providerGrantsAuthority",
        "evidenceGrantsAuthorization",
    ):
        if invariants[field] is not False:
            raise OrganizationDirectoryError(f"invariants.{field} must remain false.")
    if invariants["permissionSource"] != "canonical-role":
        raise OrganizationDirectoryError("Only canonical roles may supply permission.")
    if invariants["physicalAgentAssignmentSource"] != "team-composer":
        raise OrganizationDirectoryError("Only Team Composer may assign physical agents.")
    return directory


@lru_cache(maxsize=4)
def _load_directory_cached(path_text: str, modified_ns: int, size: int) -> dict[str, Any]:
    del modified_ns, size
    path = Path(path_text)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise OrganizationDirectoryError(f"Unable to read specialist directory: {exc}") from exc
    if not raw or len(raw) > 2 * 1024 * 1024:
        raise OrganizationDirectoryError("Specialist directory has an invalid size.")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OrganizationDirectoryError("Specialist directory must be valid UTF-8 JSON.") from exc
    return validate_directory(value)


def load_directory(path: Path = DEFAULT_DIRECTORY_PATH) -> dict[str, Any]:
    try:
        metadata = path.stat()
    except OSError as exc:
        raise OrganizationDirectoryError(f"Unable to stat specialist directory: {exc}") from exc
    validated = _load_directory_cached(str(path.resolve()), metadata.st_mtime_ns, metadata.st_size)
    return json.loads(json.dumps(validated, ensure_ascii=True, sort_keys=True))


def directory_digest(directory: dict[str, Any] | None = None) -> str:
    value = validate_directory(directory) if directory is not None else load_directory()
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def specialist_by_id(
    specialist_id: str,
    directory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = validate_directory(directory) if directory is not None else load_directory()
    normalized = _identifier(specialist_id, "specialist_id")
    for specialist in value["specialists"]:
        if specialist["id"] == normalized:
            return json.loads(json.dumps(specialist, ensure_ascii=True, sort_keys=True))
    raise OrganizationDirectoryError(f"Unknown specialist id: {normalized}")


def department_by_id(
    department_id: str,
    directory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = validate_directory(directory) if directory is not None else load_directory()
    normalized = _identifier(department_id, "department_id")
    for department in value["departments"]:
        if department["id"] == normalized:
            return json.loads(json.dumps(department, ensure_ascii=True, sort_keys=True))
    raise OrganizationDirectoryError(f"Unknown department id: {normalized}")


def specialists_for_role(
    role_id: str,
    directory: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    value = validate_directory(directory) if directory is not None else load_directory()
    role = _identifier(role_id, "role_id")
    if role not in capability_core.ROSTER_ROLE_IDS:
        raise OrganizationDirectoryError(f"Unknown canonical role id: {role}")
    return [
        json.loads(json.dumps(specialist, ensure_ascii=True, sort_keys=True))
        for specialist in value["specialists"]
        if specialist["canonicalRoleId"] == role
    ]


def directory_summary(directory: dict[str, Any] | None = None) -> dict[str, Any]:
    value = validate_directory(directory) if directory is not None else load_directory()
    role_counts = {
        role: len(
            [item for item in value["specialists"] if item["canonicalRoleId"] == role]
        )
        for role in sorted(capability_core.ROSTER_ROLE_IDS)
    }
    return {
        "schemaVersion": value["schemaVersion"],
        "directoryVersion": value["directoryVersion"],
        "directoryDigest": directory_digest(value),
        "departmentCount": len(value["departments"]),
        "specialistCount": len(value["specialists"]),
        "canonicalRoleCount": len(role_counts),
        "roleCounts": role_counts,
        "invariants": value["invariants"],
    }

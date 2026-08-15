"""Preregister, validate, and report the 18-task/216-run Beta study."""

from __future__ import annotations

import copy
import hashlib
import math
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Optional

from evals.runner.contracts import (
    RUN_CONDITIONS,
    RUN_MODES,
    TARGET_FAMILIES,
    TASK_KINDS,
    ContractError,
    canonical_digest as contract_digest,
    validate_manifest,
    validate_review,
    validate_run,
    validate_task,
)
from evals.runner.score import expected_run_binding, score_runs

from .common import (
    ProofPlaneError,
    canonical_digest,
    exact_fields,
    file_digest,
    load_json,
    rfc3339_timestamp,
    resolve_within,
)
from .evidence import load_canonical_attestation, validate_attestation_set
from .harness import HARNESS_LOCK_PATH, validate_harness_lock
from .qualification import (
    validate_image_builder_attestation_summary,
    validate_runtime_tcb_summary,
)
from .signatures import normalize_openssh_public_key, reviewer_id_digest
from .verification import (
    EVIDENCE_VERIFICATION_SIGNATURE_NAMESPACE,
    load_canonical_verification_set_receipt,
    require_verification_set_receipt_signature,
)


STUDY_SCHEMA = "jstack.eval.study-registration.v1"
EXPECTED_TASK_COUNT = 18
EXPECTED_REPETITIONS = 3
EXPECTED_RUN_COUNT = 216
REGISTRATION_REF_PREFIX = "refs/tags/proof-beta1-registration-"
LIMIT_FIELDS = (
    "wallClockSeconds",
    "tokenLimit",
    "costUsd",
    "toolCallLimit",
    "allowedToolsDigest",
)
CONDITION_TOOL_FIELDS = (
    "toolSurface",
    "proofBrokerToolsDigest",
    "proofBrokerToolCount",
    "jstackMcpToolsDigest",
    "jstackMcpToolCount",
    "jstackMcpServerSha256",
)


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ProofPlaneError("%s must be a lowercase SHA-256 digest" % field)
    return value


def _positive_integer(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ProofPlaneError("%s must be a positive integer" % field)
    return value


def _nonnegative_number(value: Any, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ProofPlaneError("%s must be a non-negative finite number" % field)
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0:
        raise ProofPlaneError("%s must be a non-negative finite number" % field)
    return normalized


def validate_registration(value: Mapping[str, Any], *, repo_root: Path) -> dict[str, Any]:
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "corpus",
            "targetJStackVersion",
            "createdAt",
            "registrationRef",
            "manifestPath",
            "schedule",
            "conditions",
            "treatment",
            "modes",
            "host",
            "executor",
            "review",
            "observation",
            "claimBoundary",
            "measurementAvailability",
            "evidencePlan",
        ),
        "study registration",
    )
    if value["schemaVersion"] != STUDY_SCHEMA:
        raise ProofPlaneError("unsupported study registration schemaVersion")
    for field in ("studyId", "targetJStackVersion", "createdAt", "registrationRef"):
        if not isinstance(value[field], str) or not value[field] or len(value[field]) > 256:
            raise ProofPlaneError("study.%s must be a non-empty string" % field)
    rfc3339_timestamp(value["createdAt"], "study.createdAt")
    if value["targetJStackVersion"] != "0.10.0-beta.1":
        raise ProofPlaneError("Beta1 study must bind JStack 0.10.0-beta.1")
    if not value["registrationRef"].startswith(REGISTRATION_REF_PREFIX):
        raise ProofPlaneError("registrationRef must use the dedicated immutable proof tag namespace")
    manifest_path = resolve_within(repo_root, value["manifestPath"], "study.manifestPath")
    if not manifest_path.is_file():
        raise ProofPlaneError("study manifest does not exist")

    corpus = value["corpus"]
    if not isinstance(corpus, dict):
        raise ProofPlaneError("study.corpus must be an object")
    exact_fields(corpus, ("id", "version", "evidenceClass"), "study.corpus")
    if corpus["evidenceClass"] != "public":
        raise ProofPlaneError("Beta1 study evidenceClass must be public")

    schedule = value["schedule"]
    if not isinstance(schedule, dict):
        raise ProofPlaneError("study.schedule must be an object")
    exact_fields(
        schedule,
        ("seedSha256", "taskCount", "repetitions", "runCount", "orderPolicy", "retryPolicy"),
        "study.schedule",
    )
    _sha256(schedule["seedSha256"], "study.schedule.seedSha256")
    if schedule["taskCount"] != EXPECTED_TASK_COUNT:
        raise ProofPlaneError("Beta1 schedule must contain exactly 18 tasks")
    if schedule["repetitions"] != EXPECTED_REPETITIONS:
        raise ProofPlaneError("Beta1 schedule must use exactly three repetitions")
    if schedule["runCount"] != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("Beta1 schedule must contain exactly 216 runs")
    if schedule["orderPolicy"] != "digest-seeded-balanced-interleave-v1":
        raise ProofPlaneError("unsupported schedule order policy")
    if schedule["retryPolicy"] != "append-only-new-attempt-never-replace":
        raise ProofPlaneError("study retries must never replace an attempt")

    conditions = value["conditions"]
    if not isinstance(conditions, dict):
        raise ProofPlaneError("study.conditions must be an object")
    exact_fields(conditions, RUN_CONDITIONS, "study.conditions")
    for condition in RUN_CONDITIONS:
        binding = conditions[condition]
        if not isinstance(binding, dict):
            raise ProofPlaneError("study.conditions.%s must be an object" % condition)
        exact_fields(binding, ("protocolPath", "protocolSha256"), "study.conditions.%s" % condition)
        protocol_path = resolve_within(repo_root, binding["protocolPath"], "condition protocol path")
        if file_digest(protocol_path) != _sha256(binding["protocolSha256"], "condition protocol digest"):
            raise ProofPlaneError("%s condition protocol digest mismatch" % condition)

    treatment = value["treatment"]
    if not isinstance(treatment, dict):
        raise ProofPlaneError("study.treatment must be an object")
    exact_fields(
        treatment,
        (
            "estimand",
            "toolSurface",
            "operationalEstimand",
            "operationalToolSurface",
            "productClaimAllowed",
            "note",
        ),
        "study.treatment",
    )
    if treatment["estimand"] != "jstack-workflow-protocol-uplift-on-codex":
        raise ProofPlaneError("Beta1 treatment must describe the workflow protocol estimand")
    if treatment["toolSurface"] != "identical-four-tool-proof-broker":
        raise ProofPlaneError("Beta1 controlled conditions must use one identical project-tool surface")
    if treatment["operationalEstimand"] != "frozen-jstack-product-surface-uplift-on-codex":
        raise ProofPlaneError("Beta1 operational estimand must bind the frozen JStack product surface")
    if treatment["operationalToolSurface"] != (
        "plain-proof-broker-vs-jstack-proof-broker-plus-exact-52-tool-mcp"
    ):
        raise ProofPlaneError("Beta1 operational tool surface is not the frozen 52-tool comparison")
    if treatment["productClaimAllowed"] is not False:
        raise ProofPlaneError("Beta1 cannot claim full installed-product uplift")
    if not isinstance(treatment["note"], str) or not treatment["note"]:
        raise ProofPlaneError("study treatment note is required")

    modes = value["modes"]
    if not isinstance(modes, dict):
        raise ProofPlaneError("study.modes must be an object")
    exact_fields(modes, RUN_MODES, "study.modes")
    for mode in RUN_MODES:
        item = modes[mode]
        if not isinstance(item, dict):
            raise ProofPlaneError("study.modes.%s must be an object" % mode)
        exact_fields(item, ("comparisonPolicy", "conditions"), "study.modes.%s" % mode)
        if not isinstance(item["conditions"], dict):
            raise ProofPlaneError("study.modes.%s.conditions must be an object" % mode)
        exact_fields(item["conditions"], RUN_CONDITIONS, "study.modes.%s.conditions" % mode)
        for condition in RUN_CONDITIONS:
            binding = item["conditions"][condition]
            if not isinstance(binding, dict):
                raise ProofPlaneError("study.modes.%s.conditions.%s must be an object" % (mode, condition))
            exact_fields(
                binding,
                LIMIT_FIELDS + CONDITION_TOOL_FIELDS,
                "study.modes.%s.conditions.%s" % (mode, condition),
            )
            _positive_integer(binding["wallClockSeconds"], "mode wall-clock budget")
            _positive_integer(binding["tokenLimit"], "mode token budget")
            _nonnegative_number(binding["costUsd"], "mode cost budget")
            _positive_integer(binding["toolCallLimit"], "mode tool-call budget")
            _sha256(binding["allowedToolsDigest"], "mode allowed-tools digest")
            _sha256(binding["proofBrokerToolsDigest"], "proof-broker tools digest")
            if not isinstance(binding["toolSurface"], str):
                raise ProofPlaneError("mode toolSurface must be a string")
            for count_field in ("proofBrokerToolCount", "jstackMcpToolCount"):
                if not isinstance(binding[count_field], int) or isinstance(binding[count_field], bool):
                    raise ProofPlaneError("mode %s must be an integer" % count_field)
            if binding["proofBrokerToolCount"] != 4:
                raise ProofPlaneError("every Beta1 condition must expose the exact four-tool proof broker")
            if binding["jstackMcpToolsDigest"] is not None:
                _sha256(binding["jstackMcpToolsDigest"], "JStack MCP tools digest")
            if binding["jstackMcpServerSha256"] is not None:
                _sha256(binding["jstackMcpServerSha256"], "JStack MCP server digest")
        plain_binding = item["conditions"]["plain"]
        jstack_binding = item["conditions"]["jstack"]
        if mode == "controlled":
            if item["comparisonPolicy"] != "equal-limits-identical-proof-broker":
                raise ProofPlaneError("controlled comparison policy must require equal limits and tools")
            if plain_binding != jstack_binding:
                raise ProofPlaneError("controlled plain and JStack condition bindings must be exactly equal")
            for binding in (plain_binding, jstack_binding):
                if (
                    binding["toolSurface"] != "proof-broker-only"
                    or binding["jstackMcpToolsDigest"] is not None
                    or binding["jstackMcpToolCount"] != 0
                    or binding["jstackMcpServerSha256"] is not None
                    or binding["allowedToolsDigest"] != binding["proofBrokerToolsDigest"]
                ):
                    raise ProofPlaneError("controlled mode must expose only the identical proof broker")
        else:
            if item["comparisonPolicy"] != "condition-specific-frozen-product-surface":
                raise ProofPlaneError("operational comparison policy must bind each condition's product surface")
            if (
                plain_binding["toolSurface"] != "proof-broker-only"
                or plain_binding["jstackMcpToolsDigest"] is not None
                or plain_binding["jstackMcpToolCount"] != 0
                or plain_binding["jstackMcpServerSha256"] is not None
                or plain_binding["allowedToolsDigest"] != plain_binding["proofBrokerToolsDigest"]
            ):
                raise ProofPlaneError("operational plain mode must expose only the proof broker")
            if (
                jstack_binding["toolSurface"] != "proof-broker-plus-jstack-mcp"
                or jstack_binding["jstackMcpToolCount"] != 52
                or jstack_binding["jstackMcpToolsDigest"] is None
                or jstack_binding["jstackMcpServerSha256"] is None
            ):
                raise ProofPlaneError("operational JStack mode must bind the exact frozen 52-tool MCP")
            if plain_binding["proofBrokerToolsDigest"] != jstack_binding["proofBrokerToolsDigest"]:
                raise ProofPlaneError("operational conditions must share the identical four-tool proof broker")
            combined_digest = canonical_digest(
                {
                    "proofBrokerToolsDigest": jstack_binding["proofBrokerToolsDigest"],
                    "proofBrokerToolCount": jstack_binding["proofBrokerToolCount"],
                    "jstackMcpToolsDigest": jstack_binding["jstackMcpToolsDigest"],
                    "jstackMcpToolCount": jstack_binding["jstackMcpToolCount"],
                    "jstackMcpServerSha256": jstack_binding["jstackMcpServerSha256"],
                }
            )
            if jstack_binding["allowedToolsDigest"] != combined_digest:
                raise ProofPlaneError(
                    "operational JStack allowed-tools digest must canonically bind the proof and exact 52-tool MCP surfaces"
                )

    host = value["host"]
    if not isinstance(host, dict):
        raise ProofPlaneError("study.host must be an object")
    exact_fields(
        host,
        ("name", "version", "model", "modelVersion", "permissionProfile", "jstackVersion"),
        "study.host",
    )
    for field, item in host.items():
        if not isinstance(item, str) or not item or len(item) > 256:
            raise ProofPlaneError("study.host.%s must be a non-empty string" % field)
    if host["jstackVersion"] != value["targetJStackVersion"]:
        raise ProofPlaneError("study host JStack version must match the target release")

    executor = value["executor"]
    if not isinstance(executor, dict):
        raise ProofPlaneError("study.executor must be an object")
    exact_fields(
        executor,
        (
            "runtime",
            "version",
            "runtimeSha256",
            "runtimeTcb",
            "isolation",
            "architecture",
            "networkPolicy",
            "policyPath",
            "policySha256",
            "runnerPath",
            "runnerSha256",
            "brokerPath",
            "brokerSha256",
            "codexConfigPath",
            "codexConfigSha256",
            "codexCliBinarySha256",
            "codexCliProvenance",
            "isolationQualificationCommandSha256",
            "isolationQualificationReceiptSetSha256",
            "imageBuilderAttestation",
            "harnessLockPath",
            "harnessLockSha256",
            "jstackMcpServerPath",
            "jstackMcpServerSha256",
            "jstackMcpToolsSha256",
            "jstackMcpToolCount",
            "maxParallel",
        ),
        "study.executor",
    )
    if executor["runtime"] != "apple-container" or executor["isolation"] != "container-vm":
        raise ProofPlaneError("Beta1 executor must use the qualified Apple container VM profile")
    if executor["networkPolicy"] != "offline-after-provisioning-canary-required":
        raise ProofPlaneError("Beta1 execution must be offline after provisioning")
    if executor["architecture"] not in ("arm64", "amd64-rosetta"):
        raise ProofPlaneError("unsupported Beta1 executor architecture")
    _sha256(executor["runtimeSha256"], "executor runtime digest")
    validate_runtime_tcb_summary(executor["runtimeTcb"], "executor runtimeTcb")
    policy_path = resolve_within(repo_root, executor["policyPath"], "executor policy path")
    if file_digest(policy_path) != _sha256(executor["policySha256"], "executor policy digest"):
        raise ProofPlaneError("executor policy digest mismatch")
    for label in ("runner", "broker", "codexConfig"):
        path = resolve_within(repo_root, executor[label + "Path"], "executor %s path" % label)
        if file_digest(path) != _sha256(executor[label + "Sha256"], "executor %s digest" % label):
            raise ProofPlaneError("executor %s digest mismatch" % label)
    _sha256(executor["codexCliBinarySha256"], "executor Codex CLI binary digest")
    if (
        not isinstance(executor["codexCliProvenance"], str)
        or not executor["codexCliProvenance"]
        or len(executor["codexCliProvenance"]) > 512
        or executor["codexCliProvenance"] != executor["codexCliProvenance"].strip()
    ):
        raise ProofPlaneError("executor Codex CLI provenance must be a bounded non-empty string")
    _sha256(
        executor["isolationQualificationCommandSha256"],
        "executor isolation qualification command digest",
    )
    _sha256(
        executor["isolationQualificationReceiptSetSha256"],
        "executor isolation qualification receipt-set digest",
    )
    validate_image_builder_attestation_summary(executor["imageBuilderAttestation"])
    if executor["harnessLockPath"] != HARNESS_LOCK_PATH:
        raise ProofPlaneError("executor must bind the fixed proof harness lock path")
    harness_lock_path = resolve_within(repo_root, executor["harnessLockPath"], "executor harness lock")
    harness_lock_digest = _sha256(executor["harnessLockSha256"], "executor harness lock digest")
    if file_digest(harness_lock_path) != harness_lock_digest:
        raise ProofPlaneError("executor proof harness lock digest mismatch")
    validate_harness_lock(load_json(harness_lock_path), repo_root=repo_root)
    jstack_server = resolve_within(repo_root, executor["jstackMcpServerPath"], "executor JStack MCP server")
    server_digest = _sha256(executor["jstackMcpServerSha256"], "executor JStack MCP server digest")
    if file_digest(jstack_server) != server_digest:
        raise ProofPlaneError("executor JStack MCP server digest mismatch")
    tools_digest = _sha256(executor["jstackMcpToolsSha256"], "executor JStack MCP tools digest")
    if executor["jstackMcpToolCount"] != 52:
        raise ProofPlaneError("executor must bind the exact 52-tool JStack MCP surface")
    operational_jstack = value["modes"]["operational"]["conditions"]["jstack"]
    if (
        operational_jstack["jstackMcpServerSha256"] != server_digest
        or operational_jstack["jstackMcpToolsDigest"] != tools_digest
        or operational_jstack["jstackMcpToolCount"] != executor["jstackMcpToolCount"]
    ):
        raise ProofPlaneError("executor and operational JStack MCP bindings must be identical")
    if _positive_integer(executor["maxParallel"], "executor maxParallel") > 2:
        raise ProofPlaneError("Beta1 maxParallel cannot exceed two before qualification")

    review = value["review"]
    if not isinstance(review, dict):
        raise ProofPlaneError("study.review must be an object")
    exact_fields(
        review,
        (
            "rubricPath",
            "rubricSha256",
            "reviewerRosterSha256",
            "minimumReviewerPoolSize",
            "signatureNamespace",
            "primaryReviewerCount",
            "blinding",
            "assignmentPolicy",
            "adjudicatorPolicy",
            "holdoutReleasePolicy",
        ),
        "study.review",
    )
    rubric_path = resolve_within(repo_root, review["rubricPath"], "review rubric path")
    if file_digest(rubric_path) != _sha256(review["rubricSha256"], "review rubric digest"):
        raise ProofPlaneError("review rubric digest mismatch")
    if review["primaryReviewerCount"] != 2 or review["blinding"] != "opaque-packets-condition-hidden":
        raise ProofPlaneError("Beta1 requires two blinded primary reviewers")
    _sha256(review["reviewerRosterSha256"], "review reviewer-roster digest")
    if review["minimumReviewerPoolSize"] != 5:
        raise ProofPlaneError("Beta1 requires at least four pair-disjoint primary reviewers and one adjudicator")
    if review["signatureNamespace"] != "jstack-beta1-review-v1":
        raise ProofPlaneError("Beta1 human reviews must use the frozen OpenSSH signature namespace")
    if review["assignmentPolicy"] != "paired-condition-primary-reviewer-sets-disjoint":
        raise ProofPlaneError("review assignment policy does not preserve independence")
    if review["adjudicatorPolicy"] != "not-primary-on-either-candidate-in-pair":
        raise ProofPlaneError("review adjudicator policy does not preserve paired-condition blinding")
    if review["holdoutReleasePolicy"] != "sealed-until-all-216-model-attempts-terminal":
        raise ProofPlaneError("holdout must remain sealed until all model attempts terminate")

    observation = value["observation"]
    if observation != {"postReleaseIncidents": "unavailable", "rollbacks": "unavailable"}:
        raise ProofPlaneError("unobserved post-release metrics must remain unavailable")
    boundary = value["claimBoundary"]
    if not isinstance(boundary, dict):
        raise ProofPlaneError("study.claimBoundary must be an object")
    exact_fields(boundary, ("upliftAllowedBeforeCompleteReview", "universalClaimsAllowed", "note"), "study.claimBoundary")
    if boundary["upliftAllowedBeforeCompleteReview"] is not False or boundary["universalClaimsAllowed"] is not False:
        raise ProofPlaneError("study claim boundaries must fail closed")
    if not isinstance(boundary["note"], str) or not boundary["note"]:
        raise ProofPlaneError("study claim-boundary note is required")
    availability = value["measurementAvailability"]
    if availability != {
        "modelCostUsd": "unavailable-chatgpt-subscription-run",
        "computeCostUsd": "unavailable-local-host-allocation",
        "queueSeconds": "unavailable",
        "backendModelSnapshot": "unavailable-provider-observable",
        "postReleaseIncidents": "unavailable-pre-release",
        "rollbacks": "unavailable-pre-release",
    }:
        raise ProofPlaneError("Beta1 measurement availability must preserve every known unavailable field")
    evidence_plan = value["evidencePlan"]
    if not isinstance(evidence_plan, dict):
        raise ProofPlaneError("study.evidencePlan must be an object")
    exact_fields(
        evidence_plan,
        (
            "bindingsPath",
            "attestationEncoding",
            "verificationPolicy",
            "verifierPublicKey",
            "verifierIdDigest",
            "verificationSignatureNamespace",
        ),
        "study.evidencePlan",
    )
    bindings_path = resolve_within(repo_root, evidence_plan["bindingsPath"], "study evidence bindings")
    if not bindings_path.is_file():
        raise ProofPlaneError("study evidence-bindings file does not exist")
    if evidence_plan["attestationEncoding"] != "canonical-json-one-file-per-run":
        raise ProofPlaneError("study evidence attestations must use canonical one-file-per-run encoding")
    if evidence_plan["verificationPolicy"] != "rehash-private-chain-and-verify-human-signatures-before-scoring":
        raise ProofPlaneError("study evidence verification policy is not fail closed")
    normalized_verifier_key = normalize_openssh_public_key(evidence_plan["verifierPublicKey"])
    if normalized_verifier_key != evidence_plan["verifierPublicKey"]:
        raise ProofPlaneError("study evidence verifier public key must use normalized OpenSSH text")
    verifier_id = _sha256(evidence_plan["verifierIdDigest"], "study evidence verifier identifier")
    if reviewer_id_digest(normalized_verifier_key) != verifier_id:
        raise ProofPlaneError("study evidence verifier identifier does not match its public key")
    if evidence_plan["verificationSignatureNamespace"] != EVIDENCE_VERIFICATION_SIGNATURE_NAMESPACE:
        raise ProofPlaneError("study evidence verification signature namespace is invalid")
    return dict(value)


def validate_evidence_bindings(
    value: Mapping[str, Any],
    *,
    study_id: str,
    expected_runs: list[Mapping[str, Any]],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProofPlaneError("evidence bindings must be an object")
    exact_fields(
        value,
        (
            "schemaVersion",
            "studyId",
            "expectedRunCount",
            "configSha256ByRun",
            "imageSha256ByTask",
            "imageStoreObservationSha256ByTask",
            "conditionSha256ByCell",
        ),
        "evidence bindings",
    )
    if value["schemaVersion"] != "jstack.eval.evidence-bindings.v1" or value["studyId"] != study_id:
        raise ProofPlaneError("evidence bindings do not match the registered study")
    if value["expectedRunCount"] != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("evidence bindings must cover exactly 216 runs")
    expected_ids = {item["runId"] for item in expected_runs}
    expected_tasks = {item["taskId"] for item in expected_runs}
    expected_cells = {"%s:%s" % (item["mode"], item["condition"]) for item in expected_runs}
    maps = (
        ("configSha256ByRun", expected_ids),
        ("imageSha256ByTask", expected_tasks),
        ("imageStoreObservationSha256ByTask", expected_tasks),
        ("conditionSha256ByCell", expected_cells),
    )
    for field, expected_keys in maps:
        mapping = value[field]
        if not isinstance(mapping, Mapping) or set(mapping) != expected_keys:
            raise ProofPlaneError("evidence bindings %s key set is incomplete" % field)
        for key, digest in mapping.items():
            _sha256(digest, "evidence bindings %s.%s" % (field, key))
    return dict(value)


def _load_tasks(manifest: Mapping[str, Any], *, repo_root: Path) -> list[dict[str, Any]]:
    tasks: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    shapes: set[tuple[str, str]] = set()
    for index, relative in enumerate(manifest["taskFiles"]):
        path = resolve_within(repo_root, relative, "manifest.taskFiles[%d]" % index)
        try:
            task = validate_task(load_json(path))
        except ContractError as exc:
            raise ProofPlaneError("invalid task file %s: %s" % (relative, exc)) from exc
        if task["taskId"] in seen_ids:
            raise ProofPlaneError("taskId values must be unique")
        shape = (task["family"], task["taskKind"])
        if shape in shapes:
            raise ProofPlaneError("task family/kind slots must be unique")
        seen_ids.add(task["taskId"])
        shapes.add(shape)
        if task["baseline"]["commit"] != task["source"]["upstreamCommit"]:
            raise ProofPlaneError("task %s baseline commit must equal its upstream commit" % task["taskId"])
        image_reference = task["environment"]["imageReference"]
        if "@sha256:" + task["environment"]["imageDigest"] not in image_reference:
            raise ProofPlaneError("task %s image reference must embed its digest" % task["taskId"])
        tasks.append(task)
    required_shapes = {(family, kind) for family in TARGET_FAMILIES for kind in TASK_KINDS}
    if len(tasks) != EXPECTED_TASK_COUNT or shapes != required_shapes:
        raise ProofPlaneError("study bundle must contain exactly all 18 family/kind task slots")
    return sorted(tasks, key=lambda item: item["taskId"])


def condition_limits(registration: Mapping[str, Any], mode: str, condition: str) -> dict[str, Any]:
    """Return the run-envelope limit binding for one study cell.

    The small legacy fallback exists only so preregistration-free plan unit
    fixtures can continue to exercise ordering.  A real registration always
    passes :func:`validate_registration`, which accepts only the nested,
    condition-bound shape.
    """

    item = registration["modes"][mode]
    if "conditions" in item:
        source = item["conditions"][condition]
        return {field: source[field] for field in LIMIT_FIELDS}
    return {field: item[field] for field in LIMIT_FIELDS}


def expected_plan(
    manifest: Mapping[str, Any],
    registration: Mapping[str, Any],
    *,
    repo_root: Path,
) -> list[dict[str, Any]]:
    tasks = _load_tasks(manifest, repo_root=repo_root)
    host_digest = canonical_digest(registration["host"])
    runs: list[dict[str, Any]] = []
    for task in tasks:
        task_digest = contract_digest(task)
        environment_digest = canonical_digest(
            {
                "imageDigest": task["environment"]["imageDigest"],
                "toolVersionsDigest": canonical_digest(task["environment"]["toolVersions"]),
            }
        )
        for mode in RUN_MODES:
            for repetition in range(1, EXPECTED_REPETITIONS + 1):
                pair_id = "%s:%s:r%d" % (task["taskId"], mode, repetition)
                for condition in RUN_CONDITIONS:
                    limits_digest = canonical_digest(condition_limits(registration, mode, condition))
                    runs.append(
                        {
                            "runId": "%s:%s" % (pair_id, condition),
                            "pairId": pair_id,
                            "taskId": task["taskId"],
                            "taskDigest": task_digest,
                            "family": task["family"],
                            "taskKind": task["taskKind"],
                            "condition": condition,
                            "mode": mode,
                            "repetition": repetition,
                            "evidenceClass": "public",
                            "hostSha256": host_digest,
                            "environmentSha256": environment_digest,
                            "limitsSha256": limits_digest,
                            "baselineCommit": task["baseline"]["commit"],
                            "hiddenTestBundleSha256": task["holdout"]["hiddenTestBundleSha256"],
                        }
                    )
    runs.sort(key=lambda item: item["runId"])
    if len(runs) != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("generated execution plan does not contain exactly 216 runs")
    return runs


def execution_schedule(expected_runs: list[Mapping[str, Any]], seed_sha256: str) -> list[dict[str, Any]]:
    """Return a frozen balanced order without changing manifest runId sorting.

    Each six-run block contains one task/mode/repetition pair from each family.
    Condition order is balanced across blocks, and the digest seed fixes every
    tie-break. The schedule is preregistered; it is never derived from results.
    """

    _sha256(seed_sha256, "schedule seed")
    pairs: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for run in expected_runs:
        pairs[str(run["pairId"])].append(run)
    grouped: dict[str, list[list[Mapping[str, Any]]]] = defaultdict(list)
    for pair_id, pair in pairs.items():
        if len(pair) != 2 or {item["condition"] for item in pair} != set(RUN_CONDITIONS):
            raise ProofPlaneError("schedule pair %s is incomplete" % pair_id)
        grouped[str(pair[0]["family"])].append(pair)
    if set(grouped) != set(TARGET_FAMILIES) or any(len(items) != 18 for items in grouped.values()):
        raise ProofPlaneError("schedule requires exactly 18 pairs per project family")

    randomizer = random.Random(int(seed_sha256, 16))
    for family in TARGET_FAMILIES:
        randomizer.shuffle(grouped[family])
    blocks = []
    for index in range(18):
        block = [grouped[family][index] for family in TARGET_FAMILIES]
        randomizer.shuffle(block)
        blocks.append(block)
    randomizer.shuffle(blocks)

    schedule: list[dict[str, Any]] = []
    ordinal = 1
    for block_index, block in enumerate(blocks):
        for pair_index, pair in enumerate(block):
            by_condition = {item["condition"]: item for item in pair}
            parity_digest = hashlib.sha256(
                (seed_sha256 + pair[0]["pairId"] + str(block_index) + str(pair_index)).encode("utf-8")
            ).digest()
            order = ("plain", "jstack") if parity_digest[0] % 2 == 0 else ("jstack", "plain")
            for condition in order:
                schedule.append(
                    {
                        "ordinal": ordinal,
                        "runId": by_condition[condition]["runId"],
                        "pairId": by_condition[condition]["pairId"],
                        "family": by_condition[condition]["family"],
                    }
                )
                ordinal += 1
    if len(schedule) != EXPECTED_RUN_COUNT or len({item["runId"] for item in schedule}) != EXPECTED_RUN_COUNT:
        raise ProofPlaneError("generated execution schedule is incomplete")
    return schedule


def freeze_manifest(
    manifest: Mapping[str, Any],
    registration: Mapping[str, Any],
    *,
    repo_root: Path,
) -> dict[str, Any]:
    normalized_registration = validate_registration(registration, repo_root=repo_root)
    bound = copy.deepcopy(dict(manifest))
    bound["corpusId"] = normalized_registration["corpus"]["id"]
    bound["corpusVersion"] = normalized_registration["corpus"]["version"]
    bound["executionPlan"] = {
        "planId": normalized_registration["studyId"],
        "evidenceClass": "public",
        "expectedRuns": expected_plan(bound, normalized_registration, repo_root=repo_root),
    }
    try:
        return validate_manifest(bound)
    except ContractError as exc:
        raise ProofPlaneError("generated manifest is invalid: %s" % exc) from exc


def validate_bundle(registration_path: Path, *, repo_root: Path) -> dict[str, Any]:
    registration = validate_registration(load_json(registration_path), repo_root=repo_root)
    manifest_path = resolve_within(repo_root, registration["manifestPath"], "study.manifestPath")
    try:
        manifest = validate_manifest(load_json(manifest_path))
    except ContractError as exc:
        raise ProofPlaneError("invalid study manifest: %s" % exc) from exc
    if manifest["corpusId"] != registration["corpus"]["id"] or manifest["corpusVersion"] != registration["corpus"]["version"]:
        raise ProofPlaneError("manifest corpus binding does not match the study registration")
    if manifest["executionPlan"]["planId"] != registration["studyId"]:
        raise ProofPlaneError("manifest planId does not match the study registration")
    generated = expected_plan(manifest, registration, repo_root=repo_root)
    if manifest["executionPlan"]["expectedRuns"] != generated:
        raise ProofPlaneError("manifest execution plan does not match its 18 task files and registration")
    schedule = execution_schedule(generated, registration["schedule"]["seedSha256"])
    return {
        "valid": True,
        "studyId": registration["studyId"],
        "taskCount": len(manifest["taskFiles"]),
        "expectedRunCount": len(generated),
        "manifestSha256": canonical_digest(manifest),
        "registrationSha256": canonical_digest(registration),
        "executionScheduleSha256": canonical_digest(schedule),
        "claimsEnabled": False,
    }


def gap_report(
    registration_path: Path,
    *,
    repo_root: Path,
    expected_run_set_path: Path,
    terminal_set_path: Path,
    task_artifact_set_summary_path: Path,
    evidence_index_path: Path,
    runs_directory: Path,
    reviews_directory: Path,
    attestations_directory: Path,
    verification_receipt_path: Path,
    verification_signature_path: Path,
) -> dict[str, Any]:
    bundle = validate_bundle(registration_path, repo_root=repo_root)
    registration = validate_registration(load_json(registration_path), repo_root=repo_root)
    manifest = validate_manifest(load_json(resolve_within(repo_root, registration["manifestPath"], "manifest")))
    schedule = execution_schedule(
        manifest["executionPlan"]["expectedRuns"],
        registration["schedule"]["seedSha256"],
    )
    expected = {item["runId"]: item for item in manifest["executionPlan"]["expectedRuns"]}
    valid_runs: dict[str, dict[str, Any]] = {}
    invalid_runs: list[dict[str, str]] = []
    extra_runs: list[str] = []
    if runs_directory.exists():
        for path in sorted(runs_directory.glob("*.json")):
            try:
                run = validate_run(load_json(path))
                unavailable_nonzero = [
                    field
                    for field, value in (
                        ("execution.modelCostUsd", run["execution"]["modelCostUsd"]),
                        ("execution.computeCostUsd", run["execution"]["computeCostUsd"]),
                        ("execution.queueSeconds", run["execution"]["queueSeconds"]),
                        ("outcome.postReleaseIncidents", run["outcome"]["postReleaseIncidents"]),
                        ("outcome.rollbacks", run["outcome"]["rollbacks"]),
                    )
                    if float(value) != 0.0
                ]
                if unavailable_nonzero:
                    raise ProofPlaneError(
                        "unavailable measurement fields must use suppressed zero placeholders, not fabricated values: %s"
                        % ", ".join(unavailable_nonzero)
                    )
                binding = expected_run_binding(run)
                if run["runId"] not in expected:
                    extra_runs.append(run["runId"])
                elif binding != expected[run["runId"]]:
                    invalid_runs.append({"path": path.name, "error": "immutable plan binding mismatch"})
                elif run["runId"] in valid_runs:
                    invalid_runs.append({"path": path.name, "error": "duplicate runId"})
                else:
                    valid_runs[run["runId"]] = run
            except (ContractError, ProofPlaneError) as exc:
                invalid_runs.append({"path": path.name, "error": str(exc)})

    valid_reviews: dict[str, dict[str, Any]] = {}
    invalid_reviews: list[dict[str, str]] = []
    extra_reviews: list[str] = []
    review_binding_errors: list[dict[str, str]] = []
    if reviews_directory.exists():
        for path in sorted(reviews_directory.glob("*.json")):
            try:
                review = validate_review(load_json(path))
                run_id = review["runId"]
                if run_id not in expected:
                    extra_reviews.append(run_id)
                elif run_id in valid_reviews:
                    invalid_reviews.append({"path": path.name, "error": "duplicate review runId"})
                elif run_id not in valid_runs:
                    review_binding_errors.append({"path": path.name, "error": "review has no valid run envelope"})
                else:
                    valid_reviews[run_id] = review
            except (ContractError, ProofPlaneError) as exc:
                invalid_reviews.append({"path": path.name, "error": str(exc)})

    valid_attestations: list[dict[str, Any]] = []
    invalid_attestations: list[dict[str, str]] = []
    if attestations_directory.exists():
        for path in sorted(attestations_directory.glob("*.json")):
            try:
                valid_attestations.append(load_canonical_attestation(path))
            except ProofPlaneError as exc:
                invalid_attestations.append({"path": path.name, "error": str(exc)})
    evidence_bindings = validate_evidence_bindings(
        load_json(resolve_within(repo_root, registration["evidencePlan"]["bindingsPath"], "evidence bindings")),
        study_id=registration["studyId"],
        expected_runs=manifest["executionPlan"]["expectedRuns"],
    )
    attestation_set_validated = False
    normalized_attestations: list[dict[str, Any]] = []
    if not invalid_attestations:
        try:
            normalized_attestations = validate_attestation_set(
                valid_attestations,
                expected_runs=manifest["executionPlan"]["expectedRuns"],
                schedule=schedule,
                study_id=registration["studyId"],
                registration_sha256=canonical_digest(registration),
                schedule_sha256=canonical_digest(schedule),
                config_sha256_by_run=evidence_bindings["configSha256ByRun"],
                image_sha256_by_task=evidence_bindings["imageSha256ByTask"],
                image_store_observation_sha256_by_task=evidence_bindings[
                    "imageStoreObservationSha256ByTask"
                ],
                condition_sha256_by_cell=evidence_bindings["conditionSha256ByCell"],
                runtime_tcb_sha256=registration["executor"]["runtimeTcb"][
                    "tcbSha256"
                ],
            )
            attestation_by_run = {item["identity"]["runId"]: item for item in normalized_attestations}
            for run_id, run in valid_runs.items():
                if attestation_by_run[run_id]["runEnvelopeSha256"] != canonical_digest(run):
                    raise ProofPlaneError("run %s differs from its evidence attestation" % run_id)
            for run_id, review in valid_reviews.items():
                if attestation_by_run[run_id]["review"]["publicReviewSha256"] != canonical_digest(review):
                    raise ProofPlaneError("review %s differs from its evidence attestation" % run_id)
            attestation_set_validated = True
        except ProofPlaneError as exc:
            invalid_attestations.append({"path": "<set>", "error": str(exc)})

    private_verification_validated = False
    private_verification_receipt: Optional[dict[str, Any]] = None
    private_verification_signature_sha256: Optional[str] = None
    private_verification_errors: list[dict[str, str]] = []
    if attestation_set_validated:
        try:
            private_verification_receipt = load_canonical_verification_set_receipt(
                verification_receipt_path,
                study_id=registration["studyId"],
                registration_sha256=canonical_digest(registration),
                schedule_sha256=canonical_digest(schedule),
                harness_lock_sha256=registration["executor"]["harnessLockSha256"],
                reviewer_roster_sha256=registration["review"]["reviewerRosterSha256"],
                evidence_verifier_id_digest=registration["evidencePlan"]["verifierIdDigest"],
                expected_run_set=expected_run_set_path,
                terminal_set=terminal_set_path,
                task_artifact_set_summary=task_artifact_set_summary_path,
                evidence_index=evidence_index_path,
                expected_runs=manifest["executionPlan"]["expectedRuns"],
                attestations=normalized_attestations,
            )
            private_verification_signature_sha256 = file_digest(verification_signature_path)
            require_verification_set_receipt_signature(
                private_verification_receipt,
                public_key_text=registration["evidencePlan"]["verifierPublicKey"],
                signer_id_digest=registration["evidencePlan"]["verifierIdDigest"],
                namespace=registration["evidencePlan"]["verificationSignatureNamespace"],
                signed_artifact=verification_signature_path,
            )
            private_verification_validated = True
        except (ProofPlaneError, OSError) as exc:
            private_verification_errors.append(
                {"path": str(verification_receipt_path), "error": str(exc)}
            )

    missing_runs = sorted(set(expected) - set(valid_runs))
    missing_reviews = sorted(set(expected) - set(valid_reviews))
    status_counts = Counter(run["execution"]["status"] for run in valid_runs.values())
    matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for run in valid_runs.values():
        matrix[run["family"]]["%s:%s" % (run["condition"], run["mode"])] += 1
    document_set_complete = not any(
        (
            missing_runs,
            missing_reviews,
            invalid_runs,
            invalid_reviews,
            extra_runs,
            extra_reviews,
            review_binding_errors,
            invalid_attestations,
            private_verification_errors,
        )
    )
    blockers = []
    terminal_count = sum(status_counts.get(name, 0) for name in ("completed", "failed", "blocked", "timed-out"))
    if terminal_count != len(valid_runs):
        blockers.append("run status accounting is not terminal")
    if missing_runs:
        blockers.append("%d planned run envelopes are missing" % len(missing_runs))
    if invalid_runs:
        blockers.append("%d run envelopes are invalid" % len(invalid_runs))
    if extra_runs:
        blockers.append("%d unplanned run envelopes are present" % len(extra_runs))
    if missing_reviews:
        blockers.append("%d blinded human-review documents are missing" % len(missing_reviews))
    if invalid_reviews:
        blockers.append("%d human-review documents are invalid" % len(invalid_reviews))
    if extra_reviews:
        blockers.append("%d reviews do not map to the frozen plan" % len(extra_reviews))
    if review_binding_errors:
        blockers.append("%d reviews lack valid run evidence" % len(review_binding_errors))
    if not attestation_set_validated:
        blockers.append("the exact 216-run private evidence-attestation set is absent or invalid")
    if not private_verification_validated:
        blockers.append(
            "the exact 216-run private evidence and all human signatures have not produced a valid verification-set receipt"
        )

    canonical_score_digest = None
    canonical_score_validated = False
    if document_set_complete and len(valid_runs) == EXPECTED_RUN_COUNT and len(valid_reviews) == EXPECTED_RUN_COUNT:
        try:
            # The canonical scorer is the final reconciliation boundary.  It
            # checks exact manifest bindings, paired-condition invariants,
            # contiguous repetitions, immutable task evidence, one-to-one
            # reviews, outcome arithmetic, and the closed score contract.
            # Counts alone can therefore never make a study score-eligible.
            score = score_runs(
                [valid_runs[run_id] for run_id in sorted(valid_runs)],
                [valid_reviews[run_id] for run_id in sorted(valid_reviews)],
                manifest=manifest,
            )
            canonical_score_digest = canonical_digest(score)
            canonical_score_validated = True
        except ContractError as exc:
            blockers.append("canonical score validation rejected the complete document set: %s" % exc)
    else:
        blockers.append(
            "canonical score validation is withheld until all 216 exact run/review bindings are valid"
        )

    eligible = bool(
        document_set_complete
        and canonical_score_validated
        and attestation_set_validated
        and private_verification_validated
        and not blockers
    )
    return {
        "schemaVersion": "jstack.eval.study-gap-report.v1",
        "studyId": bundle["studyId"],
        "eligibleForScoring": eligible,
        "expected": {"tasks": 18, "runs": 216, "reviewDocuments": 216, "primaryReviews": 432, "evidenceAttestations": 216},
        "present": {
            "validRuns": len(valid_runs),
            "validReviews": len(valid_reviews),
            "primaryReviews": len(valid_reviews) * 2,
            "evidenceAttestations": len(valid_attestations),
        },
        "runStatuses": {name: status_counts.get(name, 0) for name in ("completed", "failed", "blocked", "timed-out")},
        "matrix": {family: dict(sorted(values.items())) for family, values in sorted(matrix.items())},
        "missingRunIds": missing_runs,
        "missingReviewRunIds": missing_reviews,
        "invalidRuns": invalid_runs,
        "invalidReviews": invalid_reviews,
        "reviewBindingErrors": review_binding_errors,
        "invalidEvidenceAttestations": invalid_attestations,
        "invalidPrivateEvidenceVerification": private_verification_errors,
        "extraRunIds": sorted(extra_runs),
        "extraReviewRunIds": sorted(extra_reviews),
        "canonicalScoreValidation": {
            "performed": canonical_score_validated,
            "scoreSha256": canonical_score_digest,
            "scoreDocumentPublished": False,
        },
        "evidenceAttestationValidation": {
            "performed": attestation_set_validated,
            "attestationSetSha256": canonical_digest(valid_attestations) if attestation_set_validated else None,
            "privateChainPolicy": registration["evidencePlan"]["verificationPolicy"],
        },
        "privateEvidenceVerification": {
            "performed": private_verification_validated,
            "receiptSha256": (
                private_verification_receipt["receiptSha256"]
                if private_verification_receipt is not None
                else None
            ),
            "signatureSha256": private_verification_signature_sha256,
            "verifiedRunCount": (
                private_verification_receipt["verifiedRunCount"]
                if private_verification_receipt is not None
                else 0
            ),
            "primarySignatureCount": (
                private_verification_receipt["primarySignatureCount"]
                if private_verification_receipt is not None
                else 0
            ),
            "pairWideAdjudicatorIndependence": (
                private_verification_receipt["pairWideAdjudicatorIndependence"]
                if private_verification_receipt is not None
                else False
            ),
        },
        "measurementHandling": {
            "availability": dict(registration["measurementAvailability"]),
            "suppressedCanonicalScorePaths": [
                "efficiency.costUsd.model",
                "efficiency.costUsd.compute",
                "efficiency.costUsd.total",
                "efficiency.queueSeconds",
                "reviewOutcomes.postReleaseIncidents",
                "reviewOutcomes.rollbacks",
                "conditionBreakdown.*.efficiency.costUsd",
                "conditionBreakdown.*.efficiency.queueSeconds",
                "conditionBreakdown.*.reviewOutcomes.postReleaseIncidents",
                "conditionBreakdown.*.reviewOutcomes.rollbacks",
            ],
            "backendModelSnapshot": registration["measurementAvailability"]["backendModelSnapshot"],
            "note": (
                "The v1 run schema requires numeric placeholders for some unavailable fields. "
                "This gap report does not publish, aggregate, or interpret those placeholders as observed USD cost, "
                "queue latency, provider snapshot, incidents, or rollbacks."
            ),
        },
        "blockers": blockers,
        "claimBoundary": {
            "partialUpliftComputed": False,
            "marketingClaimAllowed": False,
            "universalClaimAllowed": False,
            "note": "A gap report never scores a partial study or removes failed, blocked, or timed-out cells from the frozen denominator.",
        },
    }

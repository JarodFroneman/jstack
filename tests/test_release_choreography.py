from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None  # type: ignore[assignment]

from mcp.jstack import release


ROOT = Path(__file__).resolve().parents[1]


def choreography(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "candidate_fingerprint": "a" * 64,
        "target_environment": "production",
        "strategy": "canary",
        "readiness_passed": True,
        "tests_passed": True,
        "review_passed": True,
        "security_passed": True,
        "browser_required": True,
        "browser_passed": True,
        "launch_required": True,
        "launch_passed": True,
        "audit_required": True,
        "audit_passed": True,
        "explicit_release_requested": True,
        "external_approval_reference_present": True,
        "rollback_plan_present": True,
        "monitoring_plan_present": True,
        "canary_plan_present": True,
    }
    values.update(updates)
    return release.build_choreography(**values)  # type: ignore[arg-type]


class ReleaseChoreographyTests(unittest.TestCase):
    def test_ready_release_still_waits_for_separate_action_authority(self) -> None:
        result = choreography()
        self.assertTrue(result["readinessPassed"])
        self.assertFalse(result["executionAuthorized"])
        by_id = {item["id"]: item["status"] for item in result["stages"]}
        self.assertEqual(
            "awaiting-separate-authority",
            by_id["external-action-authority"],
        )
        self.assertEqual("passed", by_id["canary"])
        self.assertEqual("none", result["authorityEffect"])
        release.validate_choreography(result)
        if jsonschema is not None:
            schema = json.loads(
                (ROOT / "mcp/jstack/schemas/release-choreography.v1.schema.json").read_text()
            )
            jsonschema.Draft202012Validator(schema).validate(result)

    def test_readiness_failure_blocks_action_and_missing_canary_is_visible(self) -> None:
        result = choreography(
            readiness_passed=False,
            canary_plan_present=False,
        )
        by_id = {item["id"]: item["status"] for item in result["stages"]}
        self.assertEqual("blocked-by-readiness", by_id["external-action-authority"])
        self.assertEqual("blocked", by_id["canary"])
        self.assertEqual("resolve-readiness-blockers", result["nextAction"])

    def test_tampering_or_authority_escalation_fails_closed(self) -> None:
        result = choreography()
        tampered = copy.deepcopy(result)
        tampered["executionAuthorized"] = True
        with self.assertRaisesRegex(release.ReleaseChoreographyError, "cannot authorize"):
            release.validate_choreography(tampered)

        tampered = copy.deepcopy(result)
        tampered["strategy"] = "direct"
        with self.assertRaisesRegex(release.ReleaseChoreographyError, "altered"):
            release.validate_choreography(tampered)

    def test_unknown_strategy_is_rejected(self) -> None:
        with self.assertRaisesRegex(release.ReleaseChoreographyError, "release_strategy"):
            choreography(strategy="magic")

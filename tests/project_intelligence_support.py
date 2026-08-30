from __future__ import annotations

from typing import Any
from unittest import mock


def optional_project_intelligence_applicability(*_args: Any, **kwargs: Any) -> dict[str, Any]:
    """Keep legacy contract tests isolated from the managed Graphify runtime."""
    changed_paths = [str(path) for path in kwargs.get("changed_paths", [])]
    return {
        "schemaVersion": "jstack.project-intelligence-applicability.v1",
        "mode": "auto",
        "state": "optional",
        "reason": "legacy-test-isolation",
        "mandatoryReasons": [],
        "workflowMode": str(kwargs.get("workflow_mode") or "j-stack-dev"),
        "supportedSourceCount": int(kwargs.get("supported_sources") or 0),
        "changedPathCount": len(changed_paths),
        "changedCodePathCount": 0,
        "visualizationRequired": False,
        "failClosed": False,
        "disclosureRequired": True,
    }


def isolate_legacy_test_case(test_case: Any, server: Any) -> None:
    patcher = mock.patch.object(
        server.project_intelligence_core,
        "assess_applicability",
        side_effect=optional_project_intelligence_applicability,
    )
    patcher.start()
    test_case.addCleanup(patcher.stop)

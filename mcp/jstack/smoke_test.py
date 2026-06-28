#!/usr/bin/env python3
"""Smoke test for the local jstack MCP stdio server."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SERVER = ROOT / "jstack_mcp_server.py"


def encode(message: dict) -> bytes:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    return b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body


def read_response(pipe) -> dict:
    headers = {}
    while True:
        line = pipe.readline()
        if not line:
            raise RuntimeError("MCP server closed stdout before response")
        if line in (b"\r\n", b"\n"):
            break
        key, value = line.decode("ascii").strip().split(":", 1)
        headers[key.lower()] = value.strip()
    body = pipe.read(int(headers["content-length"]))
    return json.loads(body.decode("utf-8"))


def main() -> int:
    proc = subprocess.Popen(
        [sys.executable, str(SERVER)],
        cwd=str(ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None

    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"clientInfo": {"name": "smoke-test", "version": "0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "jstack_detect_project", "arguments": {"project_path": str(ROOT.parent)}},
        },
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "jstack_plan",
                "arguments": {
                    "project_path": str(ROOT.parent),
                    "goal": "Implement an auth-sensitive production feature and prepare release checks",
                    "quality_level": "enterprise",
                    "mastery_mode": True,
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "jstack_team_plan",
                "arguments": {
                    "goal": "Build a production auth feature with tests and release checks",
                    "quality_level": "enterprise",
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "jstack_dispatch_check",
                "arguments": {
                    "goal": "Build a production auth feature with tests and release checks",
                    "explicit_release_requested": True,
                    "team": {
                        "agents": [
                            {"id": "lead", "readOnly": False, "writeScope": ["."], "task": "Orchestrate and integrate."},
                            {"id": "security", "readOnly": True, "task": "Review auth and secret risk."},
                            {"id": "qa", "readOnly": True, "task": "Verify tests and evidence."}
                        ]
                    }
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "jstack_team_plan",
                "arguments": {
                    "goal": "Build a production feature with the full JStack team",
                    "quality_level": "enterprise",
                    "team_mode": "full-team",
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "jstack_dispatch_check",
                "arguments": {
                    "goal": "Build a production feature with the full JStack team",
                    "team_mode": "full-team",
                    "coordination_packet_supplied": True,
                    "explicit_release_requested": True,
                    "team": {
                        "agents": [
                            {"id": "lead", "readOnly": False, "writeScope": ["."], "task": "Orchestrate and synthesize."},
                            {"id": "architect", "readOnly": True, "task": "Review architecture."},
                            {"id": "investigator", "readOnly": True, "task": "Trace current behavior."},
                            {"id": "builder", "readOnly": False, "writeScope": ["src/feature"], "task": "Implement bounded scope."},
                            {"id": "reviewer", "readOnly": True, "task": "Review diff."},
                            {"id": "qa", "readOnly": True, "task": "Verify tests."},
                            {"id": "security", "readOnly": True, "task": "Review trust boundary."},
                            {"id": "devops", "readOnly": True, "task": "Review release readiness."},
                            {"id": "product", "readOnly": True, "task": "Review product workflow."},
                            {"id": "quant", "readOnly": True, "task": "Review quant/data risk if applicable."},
                            {"id": "docs", "readOnly": True, "task": "Prepare handoff notes."}
                        ]
                    }
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "jstack_policy_check",
                "arguments": {
                    "project_path": str(ROOT.parent),
                    "goal": "Prepare an auth-sensitive production feature",
                    "target_environment": "local",
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "jstack_preflight",
                "arguments": {
                    "project_path": str(ROOT.parent),
                    "goal": "Prepare a production release",
                    "strict": False,
                    "run_secret_scan": False,
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "jstack_quant_backtest_review",
                "arguments": {
                    "project_path": str(ROOT.parent),
                    "strict": False,
                    "evidence": {
                        "symbol": "XAUUSD",
                        "timeframe": "M5",
                        "date_range": "2025-01-01 to 2026-06-08",
                        "data_source": "custom tick data",
                        "history_quality": 100,
                        "spread_model": "real spread",
                        "commission_model": "documented",
                        "slippage_model": "documented",
                        "source_version": "test-version",
                        "settings_file": "test.ini",
                        "out_of_sample": "documented",
                        "walk_forward": "planned",
                        "drawdown_stress_test": "planned",
                        "no_lookahead_bias_review": "done"
                    },
                },
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "jstack_release_readiness",
                "arguments": {
                    "project_path": str(ROOT.parent),
                    "goal": "Production release check",
                    "target_environment": "staging",
                    "explicit_release_requested": True,
                    "run_secret_scan": False,
                    "rollback_plan": "Revert the release artifact and restore previous config.",
                    "monitoring_plan": "Watch logs and health checks for 30 minutes."
                },
            },
        },
    ]
    for message in messages:
        proc.stdin.write(encode(message))
        proc.stdin.flush()
        if "id" not in message:
            continue
        response = read_response(proc.stdout)
        if "error" in response:
            raise RuntimeError(response["error"])
        if message["id"] == 2:
            tool_names = [tool["name"] for tool in response["result"]["tools"]]
            assert "jstack_plan" in tool_names
            assert "jstack_team_plan" in tool_names
            assert "jstack_dispatch_check" in tool_names
            assert "jstack_policy_check" in tool_names
            assert "jstack_preflight" in tool_names
            assert "jstack_security_audit" in tool_names
            assert "jstack_release_readiness" in tool_names
            assert "jstack_quant_backtest_review" in tool_names
        if message["id"] == 3:
            structured = response["result"]["structuredContent"]
            assert "jstackInstalled" in structured
        if message["id"] == 4:
            structured = response["result"]["structuredContent"]
            assert structured["qualityLevel"] == "enterprise"
            assert structured["classifications"]
            assert "requiredGates" in structured
            assert "releaseBlockers" in structured
            assert structured["masteryMode"] is True
            assert "masterySystem" in structured
            assert len(structured["masterySystem"]["stages"]) == 10
            task_training = structured["taskTraining"]
            assert task_training["masteryStage"]["stage"] >= 6
            assert task_training["learningObjective"]
            assert task_training["expertMentalModel"]
            assert task_training["skillBenchmarks"]
            assert task_training["antiSlopChecklist"]
            assert task_training["reviewRubric"]
            assert task_training["nextDrill"]
        if message["id"] == 5:
            structured = response["result"]["structuredContent"]
            assert structured["team"]["agents"]
            assert "dispatchPolicy" in structured["team"]
            assert "coordinationProtocol" in structured["team"]
        if message["id"] == 6:
            structured = response["result"]["structuredContent"]
            assert structured["valid"] is True
            assert "blockedActions" in structured
        if message["id"] == 11:
            structured = response["result"]["structuredContent"]
            assert structured["team"]["mode"] == "full-team"
            assert structured["team"]["specialistCount"] == 10
            assert len(structured["team"]["agents"]) == 11
            assert structured["team"]["coordinationProtocol"]["mode"] == "full-team"
            assert structured["coordinationProtocol"]["coreRule"].startswith("Full team means")
        if message["id"] == 12:
            structured = response["result"]["structuredContent"]
            assert structured["valid"] is True
            assert structured["teamMode"] == "full-team"
            assert structured["coordinationPacketSupplied"] is True
        if message["id"] == 7:
            structured = response["result"]["structuredContent"]
            assert "requiredChecks" in structured
            assert "blockers" in structured
        if message["id"] == 8:
            structured = response["result"]["structuredContent"]
            assert "requiredEvidence" in structured
            assert "healthSummary" in structured
        if message["id"] == 9:
            structured = response["result"]["structuredContent"]
            assert structured["readyForProductionClaim"] is True
            assert not structured["missingEvidence"]
        if message["id"] == 10:
            structured = response["result"]["structuredContent"]
            assert "releaseStandard" in structured
            assert "plans" in structured

    proc.stdin.close()
    proc.terminate()
    proc.wait(timeout=5)
    print("jstack MCP smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

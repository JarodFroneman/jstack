#!/usr/bin/env python3
"""Independent JSONL smoke test for the JStack MCP server."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SERVER = Path(__file__).resolve().with_name("jstack_mcp_server.py")


def main() -> int:
    process = subprocess.Popen(
        [sys.executable, str(SERVER)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stdin and process.stdout
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "jstack-smoke", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    responses = []
    for request in requests:
        process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        process.stdin.flush()
        if "id" in request:
            raw = process.stdout.readline()
            if raw.startswith("Content-Length"):
                raise RuntimeError("server returned legacy Content-Length framing")
            responses.append(json.loads(raw))
    process.stdin.close()
    process.wait(timeout=5)
    if process.returncode:
        raise RuntimeError(process.stderr.read())
    process.stdout.close()
    process.stderr.close()
    names = {item["name"] for item in responses[1]["result"]["tools"]}
    required = {
        "jstack_plan",
        "jstack_dispatch_check",
        "jstack_qa",
        "jstack_security_audit",
        "jstack_audit",
        "jstack_audit_finalize",
        "jstack_release_readiness",
        "jstack_launch_assess",
        "jstack_launch_evidence_register",
        "jstack_launch_finalize",
        "jstack_mastery_status",
        "jstack_loop_start",
        "jstack_loop_status",
        "jstack_loop_checkpoint",
        "jstack_loop_revise",
        "jstack_loop_stop",
        "jstack_loop_finalize",
        "jstack_program_goal_readiness",
        "jstack_program_start",
        "jstack_program_status",
        "jstack_program_next",
        "jstack_program_phase_bind",
        "jstack_program_phase_complete",
        "jstack_program_gate_challenge",
        "jstack_program_gate_resolve",
        "jstack_program_evidence_register",
        "jstack_program_pause",
        "jstack_program_resume",
        "jstack_program_revise",
        "jstack_program_cancel",
        "jstack_program_finalize",
        "jstack_external_action_challenge",
        "jstack_external_action_authorize",
        "jstack_external_action_consume",
    }
    missing = required - names
    if missing:
        raise RuntimeError(f"missing tools: {sorted(missing)}")
    if len(names) != 53:
        raise RuntimeError(f"unexpected canonical tool count: {len(names)}")
    print("jstack MCP JSONL smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

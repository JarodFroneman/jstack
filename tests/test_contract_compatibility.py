from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_contract_compatibility import DEFAULT_FIXTURE, check_contracts


class CrossVersionContractTests(unittest.TestCase):
    def test_alpha9_public_contract_snapshot_remains_compatible(self) -> None:
        self.assertEqual(check_contracts(), [])

    def test_tool_schema_drift_is_detected(self) -> None:
        fixture = json.loads(DEFAULT_FIXTURE.read_text(encoding="utf-8"))
        fixture["canonicalToolInputSchemaSha256"]["jstack_qa"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fixture.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            errors = check_contracts(path)
        self.assertIn(
            "MCP input contract changed without a versioned successor: jstack_qa",
            errors,
        )


if __name__ == "__main__":
    unittest.main()

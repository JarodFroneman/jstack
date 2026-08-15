from __future__ import annotations

import json
import unittest

from scripts.check_product_boundaries import (
    ADDITIVE_CANONICAL_TOOLS,
    CAPABILITIES,
    COMMANDS,
    CONTRACT_FIXTURE,
    ROLES,
    _load_module,
    check_boundaries,
)


class ProductBoundaryTests(unittest.TestCase):
    def test_permanent_anti_bloat_boundary(self) -> None:
        self.assertEqual(check_boundaries(), [])

    def test_product_evolves_only_at_the_named_ui_tool_boundary(self) -> None:
        fixture = json.loads(CONTRACT_FIXTURE.read_text(encoding="utf-8"))
        server = _load_module(
            "jstack_test_boundary_server",
            CONTRACT_FIXTURE.parents[3] / "mcp" / "jstack" / "jstack_mcp_server.py",
        )
        canonical = {name for name in server.TOOLS if name.startswith("jstack_")}
        aliases = {name for name in server.TOOLS if name.startswith("gstack_")}
        self.assertEqual(
            set(fixture["canonicalToolInputSchemaSha256"]) | ADDITIVE_CANONICAL_TOOLS,
            canonical,
        )
        self.assertEqual(set(fixture["legacyAliases"]), aliases)
        self.assertFalse(any(name.startswith("gstack_ui_") for name in aliases))
        self.assertEqual(5, len(COMMANDS))
        self.assertEqual(11, len(ROLES))
        self.assertEqual(18, len(CAPABILITIES))


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest

from scripts.check_product_boundaries import check_boundaries


class ProductBoundaryTests(unittest.TestCase):
    def test_permanent_anti_bloat_boundary(self) -> None:
        self.assertEqual(check_boundaries(), [])


if __name__ == "__main__":
    unittest.main()

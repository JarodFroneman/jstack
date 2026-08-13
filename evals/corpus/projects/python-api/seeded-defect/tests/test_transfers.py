from decimal import Decimal
import unittest

from src.transfers import TransferApi


class TransferApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = TransferApi()

    def test_same_user_retry_returns_the_original_transfer(self) -> None:
        original = self.api.create_transfer("user-a", "checkout-17", Decimal("12.50"))
        retry = self.api.create_transfer("user-a", "checkout-17", Decimal("12.50"))

        self.assertEqual(retry, original)
        self.assertEqual(retry.transfer_id, "tr_0001")

    def test_distinct_keys_create_distinct_transfers(self) -> None:
        first = self.api.create_transfer("user-a", "checkout-17", Decimal("12.50"))
        second = self.api.create_transfer("user-a", "checkout-18", Decimal("3.25"))

        self.assertNotEqual(first.transfer_id, second.transfer_id)

    def test_rejects_non_positive_amounts(self) -> None:
        with self.assertRaises(ValueError):
            self.api.create_transfer("user-a", "checkout-17", Decimal("0"))


if __name__ == "__main__":
    unittest.main()

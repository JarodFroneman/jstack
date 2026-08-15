"""In-memory transfer creation with idempotent retries."""

from dataclasses import dataclass
from decimal import Decimal
from typing import Dict


@dataclass(frozen=True)
class Transfer:
    transfer_id: str
    user_id: str
    amount: Decimal


class TransferApi:
    def __init__(self) -> None:
        self._next_id = 1
        self._replays: Dict[str, Transfer] = {}

    def create_transfer(
        self, user_id: str, idempotency_key: str, amount: Decimal
    ) -> Transfer:
        if not user_id or not idempotency_key:
            raise ValueError("user_id and idempotency_key are required")
        if amount <= Decimal("0"):
            raise ValueError("amount must be positive")

        existing = self._replays.get(idempotency_key)
        if existing is not None:
            return existing

        transfer = Transfer(
            transfer_id="tr_%04d" % self._next_id,
            user_id=user_id,
            amount=amount,
        )
        self._next_id += 1
        self._replays[idempotency_key] = transfer
        return transfer

"""Deterministic, standard-library-only Proof Plane runner and scorer."""

from .contracts import ContractError, canonical_digest, load_document, validate_document
from .mock import run_mock_scenario
from .score import score_runs

__all__ = [
    "ContractError",
    "canonical_digest",
    "load_document",
    "run_mock_scenario",
    "score_runs",
    "validate_document",
]

"""JStack's deterministic, read-only repository audit core.

The server integration surface is intentionally small:

``inventory_repository``
    Build a bounded content-free file manifest with secure SHA-256 identities.
``discover_adapters`` / ``get_adapter_plan``
    Return curated offline command plans; this package never executes them.
``validate_adapter_approval`` / ``make_adapter_result``
    Bind server-owned execution evidence to an exact repository subject.
``evaluate_coverage``
    Apply one fixed quick, standard, deep, or release profile fail-closed.
``normalize_findings``
    Validate candidates, enforce challenge gates, fingerprint, and deduplicate.
``finalize_audit``
    Apply exact suppressions and produce pass/fail/incomplete/error semantics.
``to_sarif``
    Project a final result into deterministic SARIF 2.1.0.

All returned textual data is secret-redacted.  Import this package as
``audit`` when it sits beside either ``mcp/jstack/jstack_mcp_server.py`` or a
generated ``plugin/mcp/jstack_mcp_server.py`` copy.
"""

from .adapters import (
    discover_adapters,
    get_adapter_plan,
    list_adapters,
    make_adapter_result,
    require_adapter_approval,
    validate_adapter_approval,
    validate_adapter_request,
)
from .benchmark import (
    BENCHMARK_ANSWER_KEY_SCHEMA_VERSION,
    BENCHMARK_CORPUS_ID,
    BENCHMARK_DIGEST_ALGORITHM,
    BENCHMARK_EVALUATION_SCHEMA_VERSION,
    BENCHMARK_FIXTURE_SET_SCHEMA_VERSION,
    BENCHMARK_MANIFEST_SCHEMA_VERSION,
    BENCHMARK_RESULT_SCHEMA_VERSION,
    BENCHMARK_SCORER_VERSION,
    BENCHMARK_SUBMISSION_SCHEMA_VERSION,
    FROZEN_ANSWER_KEY_DIGEST,
    FROZEN_FIXTURE_SET_DIGEST,
    FROZEN_MANIFEST_DIGEST,
    BenchmarkError,
    BenchmarkIntegrityError,
    load_benchmark_corpus,
    score_benchmark,
    score_benchmark_evaluation,
    validate_benchmark_submission,
)
from .controls import controls_digest, get_profile, list_profiles, load_controls
from .evidence import evaluate_coverage
from .finalizer import assess_suppression, finalize_audit, normalize_evaluated_at
from .findings import normalize_finding, normalize_findings, validate_normalized_finding
from .models import (
    ADAPTER_SUBJECT_SCHEMA_VERSION,
    COVERAGE_SCHEMA_VERSION,
    DOMAINS,
    FINDING_SCHEMA_VERSION,
    PROFILES,
    RESULT_SCHEMA_VERSION,
    AdapterError,
    AuditError,
    AuditInputError,
    FileIdentityError,
    FindingError,
    ScopeError,
    SuppressionError,
)
from .redaction import REDACTED, contains_secret_like, deep_redact, redact_text
from .sarif import to_sarif
from .scope import (
    digest_repository_file,
    inventory_repository,
    normalize_repo_path,
    normalize_scope,
    read_repository_file,
)


__all__ = [
    "ADAPTER_SUBJECT_SCHEMA_VERSION",
    "BENCHMARK_ANSWER_KEY_SCHEMA_VERSION",
    "BENCHMARK_CORPUS_ID",
    "BENCHMARK_DIGEST_ALGORITHM",
    "BENCHMARK_EVALUATION_SCHEMA_VERSION",
    "BENCHMARK_FIXTURE_SET_SCHEMA_VERSION",
    "BENCHMARK_MANIFEST_SCHEMA_VERSION",
    "BENCHMARK_RESULT_SCHEMA_VERSION",
    "BENCHMARK_SCORER_VERSION",
    "BENCHMARK_SUBMISSION_SCHEMA_VERSION",
    "COVERAGE_SCHEMA_VERSION",
    "DOMAINS",
    "FINDING_SCHEMA_VERSION",
    "PROFILES",
    "RESULT_SCHEMA_VERSION",
    "REDACTED",
    "FROZEN_ANSWER_KEY_DIGEST",
    "FROZEN_FIXTURE_SET_DIGEST",
    "FROZEN_MANIFEST_DIGEST",
    "AdapterError",
    "AuditError",
    "AuditInputError",
    "BenchmarkError",
    "BenchmarkIntegrityError",
    "FileIdentityError",
    "FindingError",
    "ScopeError",
    "SuppressionError",
    "assess_suppression",
    "contains_secret_like",
    "controls_digest",
    "deep_redact",
    "digest_repository_file",
    "discover_adapters",
    "evaluate_coverage",
    "finalize_audit",
    "get_adapter_plan",
    "get_profile",
    "inventory_repository",
    "list_adapters",
    "list_profiles",
    "load_benchmark_corpus",
    "load_controls",
    "make_adapter_result",
    "normalize_evaluated_at",
    "normalize_finding",
    "normalize_findings",
    "normalize_repo_path",
    "normalize_scope",
    "redact_text",
    "read_repository_file",
    "require_adapter_approval",
    "score_benchmark",
    "score_benchmark_evaluation",
    "to_sarif",
    "validate_adapter_approval",
    "validate_adapter_request",
    "validate_benchmark_submission",
    "validate_normalized_finding",
]

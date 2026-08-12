# Contributing

## Development

Use Python 3.9 or newer and Node.js 22 or newer for the plugin launcher test.
The project intentionally uses the Python standard library for its MCP runtime
and test suite.

Before submitting a change:

~~~text
python scripts/sync_artifacts.py --write
python scripts/sync_artifacts.py --check
python scripts/check_contract_compatibility.py
python scripts/check_product_boundaries.py
python -m evals.runner.cli verify-lock
python -m compileall -q mcp scripts tests evals
python -m unittest discover -s tests -v
python mcp/jstack/smoke_test.py
~~~

Edit canonical files under `mcp/jstack/`, `prompts/`,
`skills/jstack-dev/`, `skills/jstack-audit/`, and `mastery/`. Do not hand-edit their generated
copies under `plugin/`.

Changes to transport, policy floors, command execution, receipts, dispatch,
installers, or release readiness require adversarial regression tests.

Proof Plane changes belong under `evals/` and must remain development-only,
standard-library-only, network-free, non-executing, and absent from every
installed plugin or MCP tree. Update `evals/corpus/corpus-lock.json` whenever
any locked file changes. Do not add real-project sources,
holdout answers, private pilot data, prompts, model output, command output, or
human identities to this repository.

Audit changes must preserve deterministic output, read-only operation, stable
finding fingerprints, fail-closed incomplete coverage, and the existing secret
scanner contract. Add focused fixtures under `tests/fixtures/audit/`; never put
real credentials or live exploit targets in a fixture.

## Pull Requests

Keep diffs scoped. State behavior changed, checks run, compatibility impact,
security implications, and rollback. Never include credentials, private server
details, or fabricated test evidence.

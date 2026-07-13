# Contributing

## Development

Use Python 3.9 or newer and Node.js 22 or newer for the plugin launcher test.
The project intentionally uses the Python standard library for its MCP runtime
and test suite.

Before submitting a change:

~~~text
python scripts/sync_artifacts.py --write
python scripts/sync_artifacts.py --check
python -m compileall -q mcp scripts tests
python -m unittest discover -s tests -v
python mcp/jstack/smoke_test.py
~~~

Edit canonical files under `mcp/jstack/`, `prompts/`,
`skills/jstack-dev/`, `skills/jstack-audit/`, and `mastery/`. Do not hand-edit their generated
copies under `plugin/`.

Changes to transport, policy floors, command execution, receipts, dispatch,
installers, or release readiness require adversarial regression tests.

Audit changes must preserve deterministic output, read-only operation, stable
finding fingerprints, fail-closed incomplete coverage, and the existing secret
scanner contract. Add focused fixtures under `tests/fixtures/audit/`; never put
real credentials or live exploit targets in a fixture.

## Pull Requests

Keep diffs scoped. State behavior changed, checks run, compatibility impact,
security implications, and rollback. Never include credentials, private server
details, or fabricated test evidence.

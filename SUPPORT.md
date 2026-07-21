# Support

JStack is an open-source engineering control plane maintained on a best-effort
basis. It does not include a commercial support agreement or response-time SLA.

## Before Requesting Help

1. Confirm the issue occurs on the latest release.
2. Read the [installation guide](docs/installation.md) and relevant system
   documentation under `docs/`.
3. Run `python3 mcp/jstack/smoke_test.py` against the installed MCP payload.
4. Capture the JStack version, host/runtime surface, operating system, Python
   version, selected command, project binding mode, and sanitized error output.
5. Remove credentials, tokens, private source, and personal information from
   every log or screenshot.

## Where To Go

- Reproducible defects: use the bug report issue form.
- Product or protocol proposals: use the feature request issue form.
- Security vulnerabilities: follow [SECURITY.md](SECURITY.md), not a public
  issue.
- Contribution questions: read [CONTRIBUTING.md](CONTRIBUTING.md).

## Supported Versions

The latest published release is the supported development line. Older tags are
retained for reproducibility and rollback, but fixes are not guaranteed to be
backported.

## Support Boundary

The project can help diagnose JStack behavior. It cannot validate an entire
application as secure, compliant, profitable, production-ready, or suitable for
a regulated use case. Those decisions remain with the system owner and the
qualified reviewers responsible for that environment.

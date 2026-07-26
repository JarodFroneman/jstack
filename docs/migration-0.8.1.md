# Migrating To JStack 0.8.1

> Historical guide: v0.8.2 removes the approval mailbox, signer, tokens, and
> terminal flow described below. See [migration-0.8.2.md](migration-0.8.2.md).

JStack 0.8.1 keeps the 0.8.0 launch-assurance controls and the complete 0.7
external-action boundary. It changes only the approval transport: signed
capabilities move through a private local mailbox instead of chat.

## Operator Flow

1. Create the exact challenge as before.
2. Review the returned target and digest.
3. Run the returned `approvalCommand` in your own terminal.
4. Review the helper's exact action summary and type `APPROVE ONCE`.
5. Tell the Lead approval is complete. Do not paste a token.
6. The Lead calls `jstack_external_action_authorize` with `project_path` and
   `authorization_id`; JStack collects and removes the private response.

The old `approval_attestation` argument remains optional for compatibility,
but upgraded workflows must not ask users to paste it.

## Site Wrapper

Operators may set `JSTACK_EXTERNAL_ACTION_APPROVER_COMMAND` in the MCP launcher
to an executable such as `jstack-approve`. That wrapper should load the human's
credential outside Codex and delegate the supplied `--request-file` to
`sign_external_action_authorization.py`.

Approval requests and responses live under the existing private
`~/.jstack/external-actions/<project>/` state. Preserve that directory during
upgrade and rollback. Responses are mode `0600` and are removed after a
successful authorization.

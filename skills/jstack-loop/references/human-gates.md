# JStack Human Gates

## Trust Boundary

Human gates represent accountable decisions that machine evidence cannot make.
Codex may prepare a challenge and verify a returned signature. It must never
create the decision, handle the private key, run the signer on the approver's
behalf, or claim that silence is approval.

JStack v0.5 supports the `signed-local` identity provider. It proves possession
of a configured shared key and role; it does not provide enterprise SSO,
non-repudiation, or protection from compromise of the same operating-system
account. Organizations can replace this provider in a future protocol version.

## Configure Identities

Copy `mcp/jstack/templates/jstack.program-identities.json` to a private path
outside the repository. Map stable lowercase identity IDs to roles and to the
name of an environment variable containing that identity's key:

```json
{
  "schemaVersion": "jstack.program.identity-config.v1",
  "identities": {
    "alice": {
      "roles": ["program-owner", "risk-owner"],
      "hmacKeyEnv": "JSTACK_ALICE_APPROVER_KEY"
    }
  }
}
```

Set `JSTACK_PROGRAM_IDENTITY_CONFIG` to that file path in the MCP process
environment. Set each key environment variable to at least 32 bytes. Never put
keys in Git, policy files, prompts, MCP arguments, screenshots, logs, or chat.

## Resolve A Gate

1. Codex calls `jstack_program_gate_challenge` with the program, gate, named
   approver, decision, bounded validity, and an external approval reference.
2. JStack verifies the identity has a required role and returns
   `encodedPayload`. The payload binds program, contract, gate, identity,
   decision, reference digest, issue/expiry times, and a nonce.
3. The named person reviews the actual decision and runs the signer outside
   Codex:

```text
python ~/.codex/mcp/jstack/sign_program_approval.py \
  --encoded-payload '<encodedPayload>' \
  --key-env JSTACK_ALICE_APPROVER_KEY \
  --approver-id alice
```

The helper prints `<encodedPayload>.<signature>`. It accepts the key only from
the environment, validates every payload field and freshness window, and never
prints the key.

4. The operator returns the signed token. Codex calls
   `jstack_program_gate_resolve` with a fresh operation ID.
5. The MCP verifies signature, identity, role, quorum, decision, contract,
   gate digest, nonce, and expiry before recording the attestation digest.

Multiple roles and a quorum may be required. Distinct approver identities must
cover every required role. A fresh rejection blocks the program. Expired
approvals become pending again.

## Operational Rules

- Approval references identify an external decision record; they are not the
  private key and must not contain secrets.
- A new contract or gate digest invalidates the old signature.
- Replacing a decision after dependent work completed invalidates downstream
  proof.
- An approval does not waive machine criteria or release controls.
- A wait can last indefinitely in wall time while the active-time budget stays
  paused; freshness still applies when work resumes.

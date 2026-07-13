# Audit Mastery

Use the `audit` track without replacing or changing the default `engineering`
track. Call `jstack_mastery_start`, `jstack_mastery_status`, and
`jstack_mastery_record` with `track="audit"`.

Stages progress from safe read-only orientation, system mapping, correctness,
security, architecture, performance, supply chain, adversarial verification,
enterprise audit leadership, and finally audit-system engineering.

Reuse the 30/25/20/15/10 scoring weights for correctness, evidence, safety,
judgment, and explanation. Reuse assistance caps and independent-assessor
requirements. Fabricated/stale evidence, secret exposure, unapproved mutation,
missing artifacts, missed seeded P0 findings, false readiness claims, or an
audit pass with incomplete coverage hard-block advancement.

At Stage 9, place two structured benchmark submissions in the required
`evaluation-results.json` envelope. The MCP scores both against the pinned
synthetic corpus, compares semantic result digests, and derives the advancement
metrics. Do not submit aggregate `capstone_results` for the audit track. The
bundled answer key makes this a transparent practice benchmark, not proof of a
blind audit. Advancement additionally requires a runtime-keyed assessor
attestation bound to the exact attempt and an unseen challenge digest; two
eligible attempts must use distinct challenge digests.

The machine-readable source is `mastery/audit-curriculum.v1.json`. Existing
profile v1 data migrates atomically into `tracks.engineering`; omitted `track`
continues to select engineering.

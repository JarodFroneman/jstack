# Beta.1 blinded human review rubric v1

Two genuine independent human reviewers assess every candidate packet. AI
agents do not count as human reviewers. Packets use opaque identifiers and
exclude condition, paired run, repetition, JStack use, upstream fix, and answer
key. A private sealed map binds packet IDs to run/result/rubric digests.
The preregistered OpenSSH public-key roster contains at least five people:
four are sufficient to keep the two primary sets for a matched pair disjoint,
and at least one additional person can adjudicate without reviewing either
candidate in that pair. Canonical review submissions and required adjudication
finalizations use the fixed `jstack-beta1-review-v1` signature namespace.

Each primary reviewer records:

- accepted or rejected against the task's behaviour and change boundary;
- confirmed false finding count;
- new correctness, security, and operational findings missed at handoff;
- active review minutes and documented marginal review cost.

Reviewers inspect behaviour evidence and the candidate diff; they do not compare
against the upstream patch byte-for-byte. A reviewer must not receive both
conditions in the same matched pair; assignments are balanced across tasks,
conditions, modes, and repetitions. Reviewer identifiers are
pseudonymous SHA-256 digests; assignment records and conflicts remain private.

Disposition or metric disagreement requires a human adjudicator who was not a
primary reviewer for either candidate in that matched pair. The original
sealed reviews remain immutable. Public v1 review documents may be
emitted only after the metric vector is unanimously agreed or resolved by the
distinct adjudicator, and any disposition disagreement has been adjudicated.
If no final vector is established, the run stays unscored and the gap report
names the blocker.

Post-release incidents and rollbacks are unavailable in this pre-validation
study, not zero. Reviewers must not infer avoided production incidents or
universal quality from a benchmark result.

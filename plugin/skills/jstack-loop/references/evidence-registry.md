# JStack External Evidence Registry

## Purpose

External gates represent facts produced outside the child loop: hardware or
device tests, backtest reports, data-provider exports, certifications, legal
records, operational checks, or other bounded artifacts. JStack stores a
provenance record and digest, not the artifact itself.

## Registration Boundary

The artifact must be a regular non-symlink file inside the canonical Git
project or `~/.jstack/evidence`. It is opened without following the final
symlink where the host supports that control, hashed with SHA-256, and bounded
to 100 MB and a 30-second collection window. Declared phase outputs are also
bounded to 25 MB each and 100 MB in aggregate.

Call `jstack_program_evidence_register` with:

- the exact program and external gate IDs;
- a repository-relative or allowed absolute artifact path;
- a concise non-secret source reference; and
- a unique stable operation ID.

The server derives kind, gate and contract digests, path digest, size, hash,
collection time, validity limit, and record digest. Caller-supplied success
claims are not accepted.

## Freshness And Hash Pins

Each gate defines `evidence_kind` and `max_age_minutes`. It may pin
`required_sha256` when one exact artifact is expected. Evidence is satisfied
only while its validity window is current and any required hash matches.

An expired record remains in the audit trail but no longer satisfies the gate.
Register a new current artifact; do not edit durable state. Waiting for the
external producer pauses program active time.

## Invalidation

Replacing post-phase evidence after dependent phases completed invalidates the
affected phase's transitive dependants. Pre-phase evidence for a completed
phase cannot be replaced without a contract revision because the child ran
under a different prerequisite.

Program finalization rehashes declared child outputs and revalidates evidence
freshness. Moving, deleting, or changing an output prevents a current
completion receipt even when a historical program proof exists.

## Provenance Standard

A useful source reference identifies the external system, run or ticket, and
date without embedding credentials or personal secrets. Keep the source's own
immutable record according to organizational retention policy. JStack's local
record is evidence metadata, not a replacement for the authoritative system.

# ADR 0041: Audit Is An Independent Read-Only Assurance Department

- Status: Accepted
- Decision date: 2026-08-26
- Target program: JStack × gstack Unified Engineering OS
- Extends: [ADR 0001](0001-jstack-audit-protocol.md)

## Context

JStack already has a deep evidence-bound audit workflow. Replacing it with an
upstream review or security persona would duplicate the assurance control
plane and could let the same actor find, fix, and approve its own work.

## Decision

Retain `/jstack-audit` and its current contracts as the sole audit workflow.
Represent Audit & Assurance as a department containing logical specialists for
correctness, security, architecture, maintainability, performance,
supply-chain, and release concerns, coordinated by an Audit Lead.

Audit is read-only by definition. It may consume validated independent scanner
or provider evidence, but provider output does not become an automatic audit
PASS. Findings never authorize remediation, Git mutation, release, or
deployment. A requested fix starts or returns to a separately authorized
Builder workflow and invalidates affected candidate evidence.

Audit specialist coverage may be dynamically composed, while existing audit
stages and receipt boundaries remain authoritative and backward-compatible.

## Rejected Alternatives

- Import a second audit workflow: rejected as duplicate control plane.
- Let auditors patch findings: rejected as loss of independence.
- Treat scanner success as audit completion: rejected as incomplete assurance.

## Consequences

The richer organization is a presentation and composition layer over JStack's
existing assurance architecture, not a replacement.

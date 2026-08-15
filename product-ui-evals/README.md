# Product Interface evaluation fixtures

These fixtures exercise the public Product Interface System outside the frozen Beta.1 `evals/` and `tools/proof_plane/` roots. They are deterministic protocol examples for routing and blind visual-review tests; they contain no model outputs, human scores, release authority, or product-readiness claim.

- `task-set.v1.json` covers Editorial Calm, Creative Canvas, hybrid, preserve-and-extend, native planning, and a non-UI negative control.
- `blind-review-rubric.v1.json` defines provider-blind scoring for hierarchy, coherence, responsiveness, accessibility, platform fit, and avoidance of generic AI styling.

The fixtures are validated by `tests/test_ui_evals.py`. Runtime UI completion still requires a current `jstack_ui_finalize` receipt for the exact Git candidate and evidence set.

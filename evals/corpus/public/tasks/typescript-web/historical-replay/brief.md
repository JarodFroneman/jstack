# Hono JSON media-type replay

A request with `Content-Type: application/json; charset=utf8` and a valid JSON
body is accepted, but the parsed validator value is empty instead of containing
the submitted fields. Preserve ordinary JSON, `charset=utf-8`, structured
`+json`, and non-JSON handling. Keep the change inside the validator package,
do not weaken tests, and return evidence from the focused public suite.

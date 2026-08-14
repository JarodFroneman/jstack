# Tenant-bound idempotency

Two authenticated users can choose the same idempotency key when creating a
transfer. A retry must return the original transfer only for the same
authenticated user; one user's key must never disclose or replay another
user's transfer. Preserve validation and same-user retry behaviour. Keep the
change within the transfer API and return focused public-test evidence.

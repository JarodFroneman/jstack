# Tenant document lookup

Document identifiers are globally unique, but callers are authenticated within
a tenant. A tenant must receive a document only when both the identifier and
tenant ownership match; missing and foreign-tenant documents must have the
same not-found result. Preserve normal same-tenant lookup behaviour. Keep the
change within the document service and return focused public-test evidence.

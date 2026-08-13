CREATE TABLE documents (
    id INTEGER PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    title TEXT NOT NULL,
    archived INTEGER NOT NULL DEFAULT 0 CHECK (archived IN (0, 1))
);

CREATE INDEX documents_tenant_archived
    ON documents (tenant_id, archived, id);

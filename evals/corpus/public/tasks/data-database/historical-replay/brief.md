# sqlite-utils spaced foreign-key column replay

Adding a foreign key for a column whose name contains a space can leave the
SQLite schema malformed. Preserve the exact identifier, foreign-key metadata,
data, and `PRAGMA integrity_check`, along with ordinary identifier behaviour.
Keep the change inside table/schema transformation code and return focused
behaviour evidence.

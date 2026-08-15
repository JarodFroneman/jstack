# linenoise history resize replay

Resizing history capacity while the history length is below the old capacity
can lose existing entries. Preserve entries when growing or shrinking within
the new capacity, retain only the newest entries when necessary, and avoid
leaks or invalid pointer slots. Keep the change inside the history
implementation and return sanitizer-backed characterization evidence.

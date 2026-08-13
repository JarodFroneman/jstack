# User directory repository

Small SQLite query-safety fixture used by the Tier-1 Proof Plane.

Requires Python 3.9 or newer with the standard-library SQLite module. Run the
deterministic public suite with:

```text
python3 -m unittest discover -s tests -v
```

No package installation or external database is required. This project is
covered by the [MIT licence](../../LICENSE).

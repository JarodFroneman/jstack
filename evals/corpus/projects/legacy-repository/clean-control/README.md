# Legacy authentication token comparator

Mixed C/Python characterization fixture used by the Tier-1 Proof Plane. The C
source deliberately targets the C89 language level; Make owns the small build
and Python exercises the public behaviour through the compiled interface.

Requires Make, Python 3.9 or newer, and a C compiler. Run the deterministic
public suite with:

```text
make test
```

The project has no package dependencies and is covered by the
[MIT licence](../../LICENSE).

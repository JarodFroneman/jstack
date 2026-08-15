# Length-prefixed frame decoder

Small C systems fixture used by the Tier-1 Proof Plane.

Requires CMake 3.20 or newer and a C11 compiler. Run the deterministic public
suite with:

```text
cmake -S . -B build && cmake --build build && ctest --test-dir build --output-on-failure
```

Set `-DJSTACK_ENABLE_SANITIZERS=ON` during configuration for supported Clang
or GCC builds. This project is covered by the [MIT licence](../../LICENSE).

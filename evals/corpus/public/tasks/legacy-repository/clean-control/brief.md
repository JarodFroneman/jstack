# Legacy token-prefix report

A report claims that a supplied token can authenticate when it is only a
prefix of the stored token. Reproduce exact, prefix, suffix, and wrong-byte
cases while preserving the fixed-work comparison for equal-length values.
Change code only if a non-identical token succeeds. Keep any change within the
C comparator and return characterization-test evidence.

# Decimal counter overflow report

A report claims that an oversized decimal counter wraps into a valid 32-bit
value. Reproduce the boundary cases and preserve acceptance of canonical
decimal values from zero through `UINT32_MAX`. Change code only if overflow,
signs, suffixes, or empty values are accepted. Keep any change within the
parser and return focused public-test evidence.

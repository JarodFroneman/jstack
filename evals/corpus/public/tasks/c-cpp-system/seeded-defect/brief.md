# Exact-capacity frame decoding

Decoding a valid frame whose declared payload length exactly equals the output
buffer capacity can write outside the caller's buffer when producing a C
string. Reject insufficient capacity without modifying bytes outside the
declared output region. Preserve valid decoding, truncated-frame rejection,
and NUL termination. Keep the change within the decoder and return focused
test and sanitizer evidence.

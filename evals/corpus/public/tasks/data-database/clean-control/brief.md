# Email lookup injection report

A report claims that a crafted email value can alter the user-directory query
and enumerate other rows. Reproduce the supplied pattern as data and preserve
exact email matching. Change code only if input can alter query structure; do
not introduce manual escaping or change schema semantics. Keep any change
within the repository and return focused SQLite behaviour evidence.

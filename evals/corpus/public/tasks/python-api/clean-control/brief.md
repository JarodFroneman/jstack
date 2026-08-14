# Signed webhook verification report

A report claims that a modified or stale webhook can pass signature
verification. Reproduce the report using the documented `t=...,v1=...` header,
then preserve constant-time signature comparison and the five-minute replay
window. Change code only if an invalid request is accepted. Keep any change
within the verifier and return focused public-test evidence.

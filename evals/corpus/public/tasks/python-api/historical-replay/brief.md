# Starlette path-only URL replacement replay

Replacing the port on a path-only URL such as `/path?a=1` raises an
`IndexError`. Make port and user-information replacement safe when authority is
absent while preserving the path and query plus existing hostname, IPv6, and
port replacement behaviour. Keep the change within URL data-structure code and
return evidence from the focused public suite.

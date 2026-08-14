# NanoHTTPD explicit Content-Length replay

When application code explicitly adds a `Content-Length` header to a fixed
response, NanoHTTPD serializes the header twice. Emit exactly one length header
without changing streaming, chunking, body-length, or existing response
semantics. Keep the change within the core response implementation and return
evidence from the non-mutating focused core suite.

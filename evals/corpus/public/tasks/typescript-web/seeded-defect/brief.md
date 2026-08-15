# Local login continuation

A login callback given a continuation such as `//outside.example/account`
can send the browser away from the application origin. Accept local paths and
absolute URLs on the configured application origin, but fall back to `/` for
cross-origin, malformed, or non-HTTP destinations. Preserve path, query, and
fragment components for accepted destinations. Keep the change within the
redirect helper and return focused public-test evidence.

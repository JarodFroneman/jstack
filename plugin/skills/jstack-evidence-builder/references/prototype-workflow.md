# Isolated Prototype Workflow

Prototype output is an optional visual exploration, not production code.

1. Derive a concise design brief from the bound analysis artifact.
2. Generate at most the contracted number of standalone `html-css` or
   `html-tailwind` variants. Output must be self-contained with inline styling
   and embedded PNG, JPEG, or WebP data assets; do not load Tailwind from a CDN
   or refer to unbound local files.
3. Use no scripts, remote assets, remote fonts, analytics, forms, iframes,
   objects, embeds, network APIs, or external links/resources.
4. Render in an isolated browser context with network access disabled at every
   contracted viewport. If isolation is unavailable, omit prototypes.
5. Store HTML and PNG renders under the private reference root with exact
   hashes and sizes. Record generator/provider disclosure per prototype.
6. Select at most one retained prototype. The selection informs a later UI
   contract but never authorizes project edits or qualifies candidate evidence.

The exported HTML is deliberately a visual prototype. A later JStack
implementation must translate it into the project's actual components,
architecture, behavior, accessibility, tests, and security boundaries.

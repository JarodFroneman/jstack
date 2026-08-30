# Third-Party Notices

## gstack Unified Engineering OS Research Baseline

JStack's Unified Engineering OS integration is an original JStack governance,
contract, orchestration, provider, and evidence architecture. The following
repository was inspected at an immutable baseline for professional engineering
methods and optional runtime-provider candidates:

- Project: `garrytan/gstack`
- Repository: https://github.com/garrytan/gstack
- Pinned source commit: `ad8400543cd9ce8d07641362db48d44a95417e33`
- Pinned tree: `993294b0a09f5265d2d5af6d2fb8234ae2efe450`
- Upstream version: `1.69.0.0`
- License: MIT
- License-file SHA-256:
  `e56fbb5b3d95756f3fa1cfefa24732ec79f18ece1ad08a4e79e00df57e8b198c`

The immutable, file-level research record is generated from
`mcp/jstack/upstream/gstack/provenance-plan.v1.json` into
`mcp/jstack/upstream/gstack/provenance.v1.json`. It distinguishes researched,
adapted, wrapped, vendored, and forked material; records local targets; and
fails closed when the upstream commit, tree, license, source bytes, local
target bytes, or sync metadata do not match.

At introduction, the manifest records research and disposition only. It does
not copy or activate gstack's prompts, skills, installer, updater, router,
state, memory, telemetry, browser, Git, release, or deployment runtime. Later
adapted or wrapped behavior must add its own traceable provenance record before
its stage gate can pass.

Upstream license notice:

> MIT License
>
> Copyright (c) 2026 Garry Tan
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

## Graphify Local AST Provider

JStack optionally provisions Graphify as a separately managed local provider
for private AST graph extraction and native static HTML visualization:

- Project: `Graphify-Labs/graphify`
- Repository: https://github.com/Graphify-Labs/graphify
- Source branch: `v8`
- Pinned source commit: `680e3ed8edd3dc1fa1961050912941880b778207`
- Distribution: `graphifyy==0.9.52`
- Pinned distribution SHA-256:
  `5588ea9af433a8cf74ada89dfc0b981abf596a1327a1375fdaf661905562bf44`
- License: Apache License 2.0, with the upstream NOTICE and historical
  MIT-licensed portions retained by the installed distribution

Graphify is not vendored into JStack's standard-library core. The opt-in
installer downloads the pinned top-level wheel from Python Package Index,
verifies its hash, and installs it into a versioned isolated runtime under the
user's private `~/.jstack` directory. Its transitive binary dependencies are
resolved at installation time and are not currently covered by a complete
cross-platform JStack hash lock.

JStack invokes only local code extraction and static HTML export. It does not
invoke the upstream assistant installer or activate hosted services, semantic
providers, repository instructions, hooks, listeners, skills, or HTTP MCP.
The installed distribution carries the authoritative Apache-2.0 license and
NOTICE texts for Graphify and its included portions.

## Product UI Motion Research Reference

JStack Product UI Motion Intelligence is an original, standard-library and
stack-neutral implementation. The following repository was reviewed for
general motion-design techniques; no source code, prompts, personas, examples,
wording, installer, or repository structure is copied or adapted:

- Project: `kylezantos/design-motion-principles`
- Repository: https://github.com/kylezantos/design-motion-principles
- Reviewed source commit: `4a9ca879f24a361f4dca4174fe2da0f67b5ddee3`
- License: MIT

The research informed only general ideas such as purposeful motion,
interaction-frequency weighting, spatial continuity, reduced-motion behavior,
performance discipline, and anti-pattern review. JStack supplies its own
catalog, tokens, interaction taxonomy, schemas, receipt binding, Product UI
workflow, terminology, and deferred audit boundary. If future work copies or
adapts upstream material, its copyright and MIT license notice must be added.

## Prompt Compiler Research References

JStack's Prompt Compiler is an original standard-library implementation. The
following repositories were reviewed only for general prompt-engineering
techniques; no source code, notebooks, prompts, examples, wording, or
repository structure is copied or adapted:

- DAIR.AI Prompt Engineering Guide, revision
  `57673726396dd94acb23bdb1e67f27c78ee85a8e`, MIT:
  https://github.com/dair-ai/Prompt-Engineering-Guide
- Nir Diamant Prompt Engineering, revision
  `1d28822e826afc1f267da038e9cd677449ecfe86`, custom non-commercial licence:
  https://github.com/NirDiamant/Prompt_Engineering

The Nir Diamant repository remains research-only. Copying or adapting its
material for commercially usable JStack releases requires verified permission
and legal review.

## Screenshot To Code Design Reference

JStack Evidence Builder independently implements a private reference-bundle
contract inspired by the visual prototyping workflow of:

- Project: `abi/screenshot-to-code`
- Repository: https://github.com/abi/screenshot-to-code
- Reviewed source commit: `d026163f586dfa8c5c10d28c36edd59a9d3b0e88`
- License: MIT

No upstream application code, prompts, FastAPI/Vite runtime, provider clients,
or hosted service are embedded in JStack. The reference informed only the
general workflow ideas of multi-reference analysis, optional visual variants,
viewport rendering, and iterative comparison. JStack supplies its own schemas,
private-file verifier, receipt binding, provider disclosures, and strict
separation between source references and candidate evidence.

## Pre-Launch Checklist Sources

JStack Launch Assurance adapts and paraphrases engineering concerns from:

- Nico Burkart's reviewed 37-point pre-launch checklist:
  https://nicoburkart.notion.site/e6e88fff5ddf48a09248e2c8368445d1
- Prajwal Tomar's shared pre-launch article:
  https://x.com/PrajwalTomar_/status/2080974596392837123

JStack does not reproduce either article. It converts the reviewed concerns
into its own provider-neutral controls, risk floors, structured evidence
requirements, and safety boundaries. Vendor prescriptions and
jurisdiction-specific legal conclusions are not adopted as universal policy.

## Agency Agents

JStack's specialist capability catalog adapts selected ideas and workflow
guidance from the following project:

- Project: `msitarzewski/agency-agents`
- Repository: https://github.com/msitarzewski/agency-agents
- Pinned source commit: `459dce837db3bdfdc4763d3fefd1fd854e73c8f1`
- License: MIT

Adapted source files:

- `engineering/engineering-api-platform-engineer.md`
- `engineering/engineering-codebase-onboarding-engineer.md`
- `engineering/engineering-database-reliability-engineer.md`
- `engineering/engineering-developer-tooling-engineer.md`
- `engineering/engineering-identity-access-engineer.md`
- `engineering/engineering-incident-response-commander.md`
- `engineering/engineering-minimal-change-engineer.md`
- `engineering/engineering-multi-agent-systems-architect.md`
- `engineering/engineering-sre.md`
- `security/security-ai-generated-code-auditor.md`
- `security/security-appsec-engineer.md`
- `security/security-compliance-auditor.md`
- `specialized/specialized-workflow-architect.md`
- `strategy/coordination/handoff-templates.md`
- `testing/testing-accessibility-auditor.md`
- `testing/testing-performance-benchmarker.md`

The adaptation converts selected guidance into JStack's own role-bound,
versioned capability records, evidence requirements, stop conditions, audit
domains, loop controls, schemas, and receipt validation. It does not include the
upstream installer, bulk agent collection, personality prompts, or runtime.

Upstream license notice:

> MIT License
>
> Copyright (c) 2025 AgentLand Contributors
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.

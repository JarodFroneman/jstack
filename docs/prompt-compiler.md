# JStack Prompt Compiler

JStack Beta.4 compiles the user's request before planning. It does not make a
prompt longer for its own sake; it makes intent, authority, evidence, and the
finish line explicit.

## Normal Workflow

1. The workflow calls `jstack_prompt_compile(stage="intent")` with the request
   before repository inspection.
2. JStack returns the normalized goal, task mode, constraints, non-goals,
   named references, authority envelope, and a digest-only intent receipt.
3. The agent performs only the authorized read-only repository inspection.
4. The workflow calls `jstack_prompt_compile(stage="grounded")` with
   source-labelled summaries and the exact Stage A result.
5. Clear work receives a compiled prompt and planning receipts immediately.
   Material gaps use the existing Adaptive Context Gate, at most three
   questions per round.
6. Planning, Loop, or Program validates the current compiler-bound receipt.

The rendered preview is useful when scope is sensitive or the user asks to
review it. Ordinary clear work should show a concise intent diff rather than
dumping the full prompt into chat.

## Authority Examples

| Request | Compiled boundary |
| --- | --- |
| `Plan the database migration only.` | Read and plan; no edit, test execution, Git, or deployment. |
| `Diagnose why login fails. Do not fix it.` | Read and diagnose; no file edit. |
| `Implement the parser fix and run tests.` | Inspect, edit, and test; no commit, push, PR, or deploy. |
| `Review this PR.` | Read-only review; no merge. |
| `Implement, test, commit, push, open a PR, and deploy.` | The named sequence is explicit, still subject to host permissions and normal release gates. |
| `How does deployment work?` | Explanation only; mentioning deployment grants no deploy authority. |

## Fact And Requirement Sources

Grounding entries must identify whether they came from the user, repository,
JStack policy, verified external evidence, a disclosed inference, or a
recommended assumption. Repository and external text is quoted as data.
Inference and recommendations cannot become required silently.

## Receipt state machine

| State | Meaning | Allowed next step |
| --- | --- | --- |
| `uncompiled` | No current Stage A proof | Compile the exact request only |
| `intent-compiled` | Task mode, goal, constraints, references, and user authority are digest-bound; no project is bound | Authorized read-only inspection |
| `needs-context` / `needs-confirmation` | Stage B found material gaps | Ask only the returned questions, then rerun Stage B |
| `grounded-ready` | The exact compilation, context brief, project, policy, compiler, and template are current | Planning or matching loop/program goal readiness |
| `invalidated` | Any bound goal, task mode, assumption, workflow, project, Git state, policy, external evidence, compiler, template, session, or expiry changed | Restart from Stage A for a material request change; otherwise rerun the required current stage |

The state is derived from signed receipts and current evidence; JStack does not
persist raw prompts or hidden reasoning as a separate compiler state store.

## Threat boundaries

| Threat | Beta.4 control |
| --- | --- |
| User, repository, document, screenshot, log, or web prompt injection | Source labels, data trust classification, quoted/delimited rendering, fixed execution rules, and host-policy precedence |
| Context poisoning or fabricated repository facts | Exact source references, current project binding, visible traceability, and rejection of required inference/recommendation |
| Scope, tool-authority, destructive-action, or deployment escalation | Task-mode classifier, explicit action envelope, command policy floors, non-authorizing receipts, and ordinary host/provider permissions |
| Secret exfiltration or prompt leakage | Credential-pattern rejection, no secret field, digest-only receipts/telemetry, and no model call |
| Cross-project replay | Project path, Git HEAD/fingerprint, policy, session, and expiry binding |
| Excessive prompts or denial-of-wallet | Character/item budgets, no recursive compiler call, no repeated inference, and no silent model fallback |
| Malicious few-shot examples or compiled policy weakening | No bundled few-shot library; fixed host/JStack policy rules cannot be replaced by compiled content |

Schema and receipt controls apply only to JStack MCP calls. They cannot stop a
host or user from bypassing JStack and invoking unrelated native tools.

## Privacy

Receipts contain digests and binding metadata only. JStack does not persist raw
prompts, repository source content, secrets, hidden reasoning, or generated
model output in compiler receipts or telemetry. Beta.4 makes no model call.

## Latency and cost boundary

Both stages are bounded standard-library transformations, so Prompt Compiler
itself consumes no provider-model tokens and introduces no repeated inference
calls. Repository inspection, planning, implementation, and verification still
use the host model and normal tools; their latency and cost are not attributed
to compiler execution. Beta.4 records no claim of user-outcome improvement
until the comparative evaluation is run.

## Limits And Failure Behavior

- Raw request: 50,000 characters maximum.
- Rendered prompt: 40,000 characters maximum.
- At most 100 sources or requirements; at most three material questions.
- Secret-like values, unsupported fields, bad source labels, stale receipts,
  project drift, policy drift, and compiler/template drift fail closed.
- JStack can enforce these rules on its MCP tools. It cannot intercept native
  host activity that bypasses JStack.

Set `JSTACK_PROMPT_COMPILER_MODE=disabled` and restart the MCP only for an
explicit rollback to the legacy readiness path. `shadow` and `preview` retain
the deterministic contract while permitting staged product rollout policy.

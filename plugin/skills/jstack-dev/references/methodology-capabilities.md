# JStack Methodology Capabilities

Stage 8 adapts seven reviewed gstack methods into original, structured JStack
records: Product Discovery, CEO and Product Review, Engineering Plan Review,
Design Plan Review, Developer Experience Review, Root-Cause Investigation, and
Engineering Retrospective.

The canonical catalog is `mcp/jstack/methodologies/catalog.v1.json`. It is not
an executable prompt library. The selector is deterministic, bounded, and
stores only a digest of the normalized goal. `jstack_plan` and
`jstack_team_plan` return the selected `methodologyPlan` alongside Team
Composer output. Its catalog and selection digests are bound into the signed
Team Plan receipt and revalidated before dynamic dispatch.

For every selected record:

1. Preserve the Prompt Compiler's approved task mode, goal, constraints,
   non-goals, and authority ceiling.
2. Use only the mapped logical specialists and their existing canonical roles
   and base capabilities.
3. Follow the bounded phases in order and produce the declared output sections.
4. Satisfy the method evidence contracts or stop with the stated limitation.
5. Send any material questions through the existing Adaptive Context Gate,
   which permits at most three per round and requires recommended defaults.
6. Treat external research, browser/model providers, persistence, repository
   writes, Git, release, deployment, production, and external actions as
   separately governed operations. A methodology grants none of them.

An empty methodology selection is a valid proportional result. Do not call the
upstream gstack skills, import their host state, copy their prompt text, create
new commands, or expand the selected method into unrelated enterprise
ceremony. Root-Cause Investigation in Stage 8 supplies the bounded method.
Stage 9 now enforces its evidence-led dispatch sequence and no-random-fix gate;
read [root-cause-investigation.md](root-cause-investigation.md) whenever that
method is selected.

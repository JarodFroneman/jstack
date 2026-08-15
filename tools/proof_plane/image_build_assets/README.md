# Beta.1 image-build assets

This directory is the repository-controlled half of the 18-task Linux/arm64
image input boundary.

- `build-input-plan.json` is canonical JSON plus one LF. It binds the exact 18
  task IDs, current canonical Tier-1 source tar digests, reviewed historical
  source/base pins, exact qualified-tool sets, and required component slots.
- `jstack_mcp_tools.json` is canonical JSON with no trailing LF. Its raw
  SHA-256 is the runtime `jstackMcpToolsSha256`; the build-input audit probes
  `mcp/jstack/jstack_mcp_server.py` and requires byte-for-byte equality with
  these 52 sorted descriptors.
- `Containerfile.tmpl` is not itself buildable. The only substitutions are one
  reviewed digest-pinned base reference and a sorted set of local rootfs-tar
  `ADD` statements. The renderer rejects unresolved tokens and any instruction
  outside `FROM`, `ADD`, `COPY`, `ENV`, and `WORKDIR`.

Do not add production package archives, base-image exports, Apple `container`
binaries, compiled canaries, policy reviews, licence evidence, or private study
artifacts here. Those are external reviewed inputs and are admitted only by
`tools.proof_plane/image_build_inputs.py`. A missing artifact is a blocker, not
a value to fill with a sample or placeholder digest.

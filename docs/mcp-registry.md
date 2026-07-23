# MCP Registry listing

SysKnife's MCP server is the `sysknife mcp-server` subcommand (stdio). This note
records how it maps onto the official [MCP Registry](https://registry.modelcontextprotocol.io)
and the exact steps to publish a listing.

> The official registry is in **preview** — it may reset data before general
> availability, so treat a published entry as non-permanent for now.

## Distribution: the `cargo` package type

The registry supports a `cargo` package type: `registryType` is an open string
(the schema's enumerated examples are only npm/pypi/oci/nuget/mcpb, so `cargo`
is permitted rather than listed), and the registry validator
(`internal/validators/registries/cargo.go`) implements it. That lets us list the
crate directly:

- `registryType`: `cargo`, `identifier`: `sysknife-cli` (the crate that installs
  the `sysknife` binary), `transport`: `stdio`.
- Because `sysknife`'s MCP server is a subcommand, the package entry passes
  `mcp-server` as a positional `packageArguments` value. A client resolves the
  listing to `cargo install sysknife-cli` then runs `sysknife mcp-server`.

This supersedes the earlier npm-launcher plan: the npm package `sysknife-setup`
is an installer/wizard, not a stdio server, and `npx sysknife-setup` would launch
the wizard rather than the server. The `cargo` type avoids that entirely — no
dedicated launcher package is needed.

Namespace: `io.github.lacs-project/sysknife` (verified by GitHub identity — the
authenticating account must belong to the `lacs-project` org; no DNS needed).

## Ownership marker (already in place)

crates.io ownership is proven by a visible `mcp-name:` token in the crate's
**rendered** README. crates.io strips HTML comments when rendering, so the
marker must be plain text — `apps/sysknife-cli/README.md` carries:

```
mcp-name: io.github.lacs-project/sysknife
```

The verifier fetches `https://crates.io/api/v1/crates/sysknife-cli/<version>/readme`
and searches the rendered README for that token. **The marker only takes effect
in a *published* crate version**, so the `server.json` `version` must match a
crate version whose README carries it (see the release step below).

## `server.json`

Not shipped as a root file: the `version` is coupled to a published crate
version that carries the marker, so it is finalized at release time. Template:

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
  "name": "io.github.lacs-project/sysknife",
  "description": "Let AI operate your Linux box through typed, approval-gated, Ed25519-audited actions instead of shell strings.",
  "repository": {
    "url": "https://github.com/lacs-project/sysknife",
    "source": "github"
  },
  "version": "0.2.6",
  "packages": [
    {
      "registryType": "cargo",
      "registryBaseUrl": "https://crates.io",
      "identifier": "sysknife-cli",
      "version": "0.2.6",
      "transport": { "type": "stdio" },
      "packageArguments": [
        { "type": "positional", "valueHint": "subcommand", "value": "mcp-server" }
      ]
    }
  ]
}
```

## Publish steps

The crate README marker (`apps/sysknife-cli/README.md`) is already in the repo,
so the next crate release is registry-ready. To publish the listing:

1. **Release a crate version that carries the marker.** The marker landed after
   0.2.5, so cut the next version (e.g. 0.2.6) via the normal tag-driven
   release; that publishes `sysknife-cli` with the marker in its README. Confirm
   the README ships in the packaged crate first
   (`cargo package -p sysknife-cli --list | grep README.md`), then set the
   `version` fields in `server.json` to that version.
2. **Install the publisher CLI:**
   ```sh
   brew install mcp-publisher   # or download from the registry's GitHub Releases
   ```
3. **Authenticate as the `lacs-project` org** — pick one:
   - Local, interactive (one-time device-flow login in a browser):
     ```sh
     mcp-publisher login github
     ```
   - CI, headless (no stored secret), inside a GitHub Actions job with
     `permissions: id-token: write` (the `./` reflects the binary downloaded
     into the job's working directory rather than a PATH install):
     ```sh
     ./mcp-publisher login github-oidc
     ```
4. **Validate and publish** (from the repo root, with `server.json` present):
   ```sh
   mcp-publisher validate
   mcp-publisher publish
   ```
5. **Verify:**
   ```sh
   curl "https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.lacs-project/sysknife"
   ```

## Downstream propagation

One publish to the official registry auto-propagates to the **GitHub MCP
Registry** and **PulseMCP** (they ingest from it). Glama, mcp.so, Smithery,
LobeHub, and mcpservers.org still take **separate manual submissions** for
maximum reach.

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
the wizard rather than the server. Worse than merely wrong, the wizard reads
answers from stdin when stdin is not a TTY, so it would consume a client's
`initialize` frame as a prompt answer. The `cargo` type avoids that entirely: no
dedicated launcher package is needed.

The root `server.json` is accepted by `mcp-publisher validate`, which checks
against the live registry rather than only the local schema.

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

Shipped at the repository root. The `version` is coupled to a published crate
version that carries the marker, and two checks keep that coupling honest:

- `scripts/check_release_versions.sh` includes both `server.json` version fields
  in the release-wide version comparison, so a release cannot bump the crates
  and leave the listing pointing at the previous version.
- `tests/release/registry-manifest.test.sh` asserts the rest of the manifest:
  `registryType`/`registryBaseUrl`/`transport`, that the identifier is the CLI
  crate, that the `mcp-server` positional argument is present, and that the
  ownership marker is in the crate README **outside** an HTML comment. It runs
  in CI and in the release preflight.

Both mean a stale or incoherent listing fails a check rather than a publish.

## Publish steps

The crate README marker (`apps/sysknife-cli/README.md`) is in the repo and has
shipped in every published crate since 0.2.6, so any current version is
registry-ready. To publish the listing:

1. **Confirm the marker is live in the version `server.json` names.** The
   validator reads the *rendered* README from crates.io, in two calls:
   ```sh
   version=0.2.14
   ua='sysknife-release/1.0 (https://github.com/lacs-project/sysknife)'
   url="$(curl -sS -H 'Accept: application/json' -H "User-Agent: $ua" \
     "https://crates.io/api/v1/crates/sysknife-cli/${version}/readme" \
     | node -p 'JSON.parse(require("fs").readFileSync(0,"utf8")).url')"
   curl -sS -H "User-Agent: $ua" "$url" \
     | grep -c 'mcp-name: io.github.lacs-project/sysknife'
   ```
   A count of `1` means the marker is visible to the validator. A `0` means the
   listing cannot be published for that version, whatever the repo says.
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
4. **Validate and publish** (from the repo root):
   ```sh
   mcp-publisher validate   # checks server.json against the live registry
   mcp-publisher publish
   ```
   `validate` needs no authentication, so it is worth running before the login
   step. Only `publish` requires the token.
5. **Verify:**
   ```sh
   curl "https://registry.modelcontextprotocol.io/v0/servers?search=sysknife"
   ```
   The `count` in the response metadata goes from `0` to `1`.

## Downstream propagation

One publish to the official registry auto-propagates to the **GitHub MCP
Registry** and **PulseMCP** (they ingest from it). Glama, mcp.so, Smithery,
LobeHub, and mcpservers.org still take **separate manual submissions** for
maximum reach.

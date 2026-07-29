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
- Two things that install implies, and which the registry entry has no field for:
  it needs a C compiler (`build-essential`; **not** cmake, verified in clean
  Ubuntu containers) and takes 7 to 12 minutes; and the CLI alone can plan but
  not execute, because execution belongs to the privileged `sysknife-daemon`.
  Both are stated up front in `apps/sysknife-cli/README.md`, which is the page
  crates.io renders and therefore what a registry visitor actually reads.

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
   # Read the version from the manifest rather than retyping it: checking the
   # marker for a version other than the one being published proves nothing.
   version="$(node -p 'require("./server.json").version')"
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
Registry** and **PulseMCP**, which ingest from it. Everything else takes a
separate submission. Verified by walking each flow on 2026-07-29:

| Directory | How it takes a server |
|---|---|
| **PulseMCP** | No submission form exists for servers. Choosing "MCP Server" on `pulsemcp.com/submit` returns instructions only: they ingest the official registry daily and process weekly. The URL field on that page belongs to the *MCP Client* branch. Email `hello@pulsemcp.com` only if a week has passed since the registry publish without a listing. |
| **mcpservers.org** | Web form: server name, one-sentence description, link, category, contact email. Free tier with a review pass; a paid tier only buys queue position. |
| **Glama** | Browser-only build spec at `glama.ai/mcp/servers/lacs-project/sysknife/admin/dockerfile`. Keep the `mcp-proxy --` prefix in the CMD arguments: that wrapper is how Glama exposes a stdio server. |
| **Smithery** | `smithery.yaml` is in the repository root, declaring the **stdio** form: their CLI spawns `sysknife mcp-server` on the user's own machine, where a daemon can actually exist. Their two *hosted* runtimes (`typescript`, `container`) require Streamable HTTP and would run a daemonless sandbox, so they are the wrong shape here, and `tests/release/smithery-manifest.test.sh` fails the build if someone switches to one. The user still needs the `sysknife` binary installed first; Smithery spawns it, it does not install it. |
| **mcp.so, LobeHub** | Separate submissions; both reject automated fetches, so use a real browser. |

## Sandboxed directories and the empty tool list

Most directories work the same way: build a container from the repository, boot
the server inside it, introspect the tool list, and score what they find. That
model assumes a self-contained server, one that reaches an API over the network
or reads files inside its own sandbox. SysKnife is not that, by design, and the
consequence shows up on those pages as an empty tool list.

`sysknife mcp-server` is the **unprivileged** half of the system. It plans,
previews, renders, and forwards. It cannot change anything. Every mutation
travels over a unix socket to `sysknife-daemon`, which holds the sudoers, polkit
and helper policy that `sudo make install` owns, and the socket itself is
`0750 sysknife:sysknife` at `/run/sysknife/daemon.sock`. That split is the
product: it is why an agent cannot hand a shell string to root, and why every
executed action lands in the signed chain. See
[Architecture & Trust Boundaries](architecture.md).

Three things follow, and all three are expected rather than broken:

1. **No daemon in the sandbox, so no tools.** With nothing listening on the
   socket, `sysknife doctor` correctly reports it absent and the tool list comes
   back empty. A directory showing `"tools": []` for SysKnife is reporting the
   truth about its own container, not a fault in the server.
2. **stdio needs a wrapper.** Container-based hosts front the binary with a
   proxy (Glama uses `mcp-proxy --`). Strip that prefix while editing a build
   spec and the listing stops working.
3. **A green sandbox run would prove nothing anyway.** The host under
   administration would be a throwaway container, so "it booted and listed five
   tools" carries no information about whether SysKnife administers a real
   Ubuntu machine correctly.

The practical guidance: treat these listings as **discovery surface**, not as
validation. They are cheap inbound links from where people look for MCP servers.
The evidence that actually bears on correctness lives elsewhere: the VM runs
recorded in [Distro Support](distro-support.md), the story suite, and an audit
chain a third party can verify with only the public key.

And the inverse, which matters more: **do not relax the daemon boundary to score
better in a sandbox.** A version of SysKnife that enumerated tools and mutated
state from inside an unprivileged container would score higher on those pages and
would no longer be worth installing.

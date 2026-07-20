# MCP Registry listing

SysKnife's MCP server is the `sysknife mcp-server` subcommand (stdio). This note
records how it maps onto the official MCP Registry and the one open step before
we publish a listing.

## The launch model

The registry runs an npm package's default `npx <name>` bin and treats its
stdio as the MCP stream. `sysknife-setup`'s default bin is the interactive setup
wizard, not a server, so it cannot itself be the registry entry.

`sysknife-setup` therefore ships a second bin, `sysknife-mcp`, that locates the
installed `sysknife` binary and execs `sysknife mcp-server` with inherited
stdio:

```sh
npx -p sysknife-setup sysknife-mcp
```

If the binary is not installed it exits with guidance to run `npx sysknife-setup`
first. The server also needs the privileged daemon running (a systemd service
the wizard installs); this launcher starts the server front-end, not the daemon.

## Remaining step (post-launch, deferred)

The registry `server.json` runs `npx <identifier>` (the package's default bin)
and has no field to select a non-default bin. Two clean options, decide before
submitting:

1. Publish a tiny dedicated `sysknife-mcp` npm package whose default bin is the
   launcher, so `npx sysknife-mcp` just works. Costs a second npm
   trusted-publisher setup.
2. Keep the launcher inside `sysknife-setup` and validate whether the registry
   runner can be told to invoke it via `runtime_arguments`
   (`-p sysknife-setup sysknife-mcp`) with a live `mcp-publisher` dry-run.

Namespace: `io.github.lacs-project/sysknife` (GitHub OIDC via the lacs-project
org). `packages/setup/package.json` carries the matching `mcpName` for
verification.

Draft manifest:

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-07-09/server.schema.json",
  "name": "io.github.lacs-project/sysknife",
  "description": "Let AI operate your Linux box without ever handing it a shell.",
  "version": "0.2.5",
  "repository": { "url": "https://github.com/lacs-project/sysknife", "source": "github" },
  "packages": [
    { "registry_type": "npm", "identifier": "sysknife-mcp", "version": "0.2.5", "transport": { "type": "stdio" } }
  ]
}
```

This is intentionally not shipped as a root `server.json`: it needs the package
published and a live publisher run first, and a root manifest pointing at
`sysknife-setup` would make clients launch the wizard instead of a server.

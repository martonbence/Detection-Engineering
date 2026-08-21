# MCP server setup for this repo

Three of the team's specialist agents depend on MCP tools that aren't part of
Claude Code's built-in tool set:

| Agent | Depends on | Needs auth? |
|---|---|---|
| `kai-github-ops` (Kai) | `github` MCP server (`mcp__github__*`) | Yes — a GitHub token |
| `priya-security-scanner` (Priya) | `semgrep` MCP server (`mcp__semgrep__*`) | No |
| `sienna-frontend-engineer` (Sienna) | `playwright` and `chrome-devtools` MCP servers | No |

The project ships a checked-in [`.mcp.json`](../.mcp.json) at the repo root
that declares all four servers, so a fresh clone gets the same tool set
instead of silently losing most of these three agents' capabilities (see
`audit/feature-and-process-audit.md` item 5.4 for the finding this closes).
`.mcp.json` contains **no literal secrets** — the one server that needs auth
reads it from an environment variable. Each server below still needs a
one-time local setup step before its tools actually work; `.mcp.json` alone
does not install anything.

## `github` — needs a token, one-time

The GitHub MCP server is Claude Code's remote HTTP server
(`https://api.githubcopilot.com/mcp`). `.mcp.json` sends
`Authorization: Bearer ${GITHUB_TOKEN}` — Claude Code expands `${VAR}` from
your shell environment at connect time, so the real token never has to live
in a file that gets committed.

**One-time setup**, once per machine/user (or once per CI environment/secret store):

1. Create a GitHub token with at least these scopes, matching what Kai's
   tool list actually exercises (PRs, issues, branches, releases, repo
   collaborators/teams, code/commit search, file writes):
   `repo`, `read:org`, `project`, `gist`.
   - A classic PAT (Settings → Developer settings → Personal access tokens)
     works. So does `gh auth token` if you already run `gh auth login`
     locally — but treat that as a convenience, not the intended CI path;
     see the caveat below.
2. Export it as `GITHUB_TOKEN` in your shell profile (or your CI
   environment/secret store) before starting Claude Code:
   ```
   export GITHUB_TOKEN=ghp_xxx...
   ```
3. Start (or restart) Claude Code from a shell that has that variable set,
   and confirm with `claude mcp list` that `github` shows as connected.

**Caveat — this is not fully hands-off, and that's expected.** Getting the
token itself (step 1) is an interactive, human action on github.com or via
`gh auth login` — there's no way to express "mint yourself a token" as a
line in `.mcp.json`. What *is* now portable is everything after that: once
a token exists, it's one env var and the same config works on any machine
or in CI. This matches the finding's framing — the secret-via-env-var half
is the easy, portable case; only the human act of obtaining the token in
the first place is inherently manual.

**Caveat — local-scope override.** Claude Code supports multiple config
scopes (user, project `.mcp.json`, and a per-project "local" scope stored
privately in `~/.claude.json`). If a machine already has a `github` server
configured at local/project scope for this repo (e.g. added earlier via
`claude mcp add` or an onboarding "Install GitHub App" flow), that
local-scope entry takes precedence over this checked-in `.mcp.json` on that
machine — the committed config only takes effect where no such override
exists (a fresh clone, a different machine, CI). If `github` tools behave
unexpectedly on an existing dev machine after this file is added, check
`claude mcp list` and that machine's local-scope config before assuming
`.mcp.json` is broken.

## `semgrep` — no auth, needs the CLI installed

`.mcp.json` just runs `semgrep mcp`, i.e. the MCP subcommand built into the
`semgrep` CLI itself (not the old, separately-deprecated `semgrep-mcp`
package). No token is configured or required for local scanning
(`semgrep_scan`, `semgrep_scan_with_custom_rule`, `semgrep_scan_supply_chain`,
etc. all run against local rules/code).

**One-time setup:** install the `semgrep` CLI so it's on `PATH`, e.g.
`pipx install semgrep` (this is how it's installed in the current dev
environment) or `pip install semgrep`. If a future need requires Semgrep's
hosted AppSec Platform features (e.g. `semgrep_findings` pulling
platform-side data rather than local results), that would need a
`SEMGREP_APP_TOKEN` — out of scope today since the current config runs
CLI-only.

## `playwright` — no auth, needs a browser installed

`.mcp.json` runs `npx -y @playwright/mcp@latest` with no
`--executable-path` override. The version in this machine's user-scope
config hardcoded a path to one specific locally-installed Chromium build
(`~/.cache/ms-playwright/chromium-1228/...`) — that path is machine- and
install-specific, so it was deliberately **not** carried into the checked-in
config; committing it verbatim would have pointed every other machine at a
Chromium build that doesn't exist there. Omitting the flag lets the
Playwright MCP server manage its own bundled browser instead.

**One-time setup:** run `npx playwright install chromium` once per machine
(or let the MCP server trigger the download on first use, if your `npx`
setup allows that without a prior explicit install — behavior here can vary
by Playwright MCP version, so if `browser_navigate` fails on first use, run
the explicit install command and retry).

## `chrome-devtools` — no auth, no config needed

`.mcp.json` runs `npx -y chrome-devtools-mcp@latest` as-is; this was
already portable in the user-scope config (no hardcoded paths, no secrets).
It launches/attaches to a local Chrome instance via CDP. No setup beyond
having Node/`npx` available.

## Verifying the setup

After setting `GITHUB_TOKEN` and installing `semgrep`/Playwright's browser,
restart Claude Code from that shell and run `claude mcp list`. All four
servers should show `Connected`. If `github` shows an auth error, re-check
`GITHUB_TOKEN` is exported in the *same* shell Claude Code was launched
from (not just a different terminal) and that the token has the scopes
listed above.

## Things this doc deliberately does not solve

- **Network egress in CI.** `playwright` and `chrome-devtools` both invoke
  `npx -y ...@latest`, which fetches from the npm registry at connect time.
  A network-restricted CI runner needs either egress allowed to npm, or
  those packages pre-installed/cached and the `args` changed to drop
  `-y ...@latest` in favor of a pinned local install — not attempted here
  since it's a CI-environment decision, not a config-portability one.
- **Version pinning.** All three `npx`/CLI-based servers float on `@latest`
  or whatever `semgrep` is installed, matching current user-scope behavior
  exactly. Pinning versions would be a separate, deliberate hardening step
  or scope for `jamal-devops-engineer`/`priya-security-scanner`, not a
  requirement for portability.

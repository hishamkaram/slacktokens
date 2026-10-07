# slacktokens

Extract personal Slack workspace tokens (`xoxc-...`) and the authentication cookies (`d`, `d-s`) from the Slack desktop app's local storage.

Copyright (C) 2026 Hesham Karm. Released under [GPL-3.0-or-later](./LICENSE).

This is a Go port of [hraftery/slacktokens](https://github.com/hraftery/slacktokens) — the original Python implementation by Heath Raftery (2021). The port matches the upstream public surface, ships a CLI, and adds verified-against-current-Chromium crypto plus the test suite the original lacks. Per GPLv3, the upstream copyright is preserved and this port is also distributed under GPLv3.

> Not endorsed or authorised by Slack Technologies LLC.

## Status

| Platform | Library | CLI |
| --- | --- | --- |
| macOS (Intel + Apple Silicon) | ✅ | ✅ |
| Linux (libsecret) | ✅ | ✅ |
| Windows (DPAPI) | ✅ | ✅ |

Verified against Slack 4.50 / Electron 42 / Chromium 148.

Windows uses a different crypto path: AES-256-GCM with a master key stored in `Local State` and wrapped with DPAPI. Slack's Electron does **not** ship Chromium's v20 "app-bound encryption" infrastructure, so cookies remain v10/v11 — extractable from your own user account without elevation. v20 is detected and rejected with a clear error.

## Install

**Homebrew (macOS / Linux):**

```sh
brew install hishamkaram/slacktokens/slacktokens
```

**Debian / Ubuntu (.deb):** download the architecture-matching `.deb` from the [latest release](https://github.com/hishamkaram/slacktokens/releases/latest), then:

```sh
sudo dpkg -i slacktokens_v*_linux_amd64.deb   # or linux_arm64.deb
```

**Pre-built binaries (Windows, or unmanaged Linux/macOS):** download from the [releases page](https://github.com/hishamkaram/slacktokens/releases/latest) and extract.

**Go (library or CLI):**

```sh
go get github.com/hishamkaram/slacktokens                                # library
go install github.com/hishamkaram/slacktokens/cmd/slacktokens@latest     # CLI
go install github.com/hishamkaram/slacktokens/cmd/slacktokens-mcp@latest # MCP server
```

## Library usage

```go
package main

import (
    "encoding/json"
    "fmt"
    "os"

    "github.com/hishamkaram/slacktokens"
)

func main() {
    res, err := slacktokens.GetTokensAndCookie()
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
    json.NewEncoder(os.Stdout).Encode(res)
}
```

Public API:

```go
func GetTokens()         (map[string]Workspace, error)
func GetCookie()         (Cookie, error)              // parity with Python: returns "d" only
func GetCookies()        ([]Cookie, error)            // returns d and d-s when present
func GetTokensAndCookie() (Result, error)
```

Sentinel errors (use with `errors.Is`):

```go
slacktokens.ErrUnsupportedOS
slacktokens.ErrProfileNotFound      // no Slack profile dir found (lists candidates)
slacktokens.ErrLocalConfigMissing
slacktokens.ErrLocalConfigParse
slacktokens.ErrCookieNotFound
```

## CLI

```sh
slacktokens                # full Result as indented JSON
slacktokens -tokens        # tokens map only
slacktokens -cookie        # the d cookie only (parity with Python)
slacktokens -cookies       # d + d-s
slacktokens -out creds.json # write the full Result to a new 0600 file (refuses to overwrite)
```

`-out` is the human-run way to get credentials into a file. The MCP server
never writes or returns credentials (see below), so when you want them on disk
you run this yourself. The write is atomic (temp file → fsync → rename) and
refuses to overwrite an existing file. Mode `0600` restricts access by Unix
permission bits only; on Windows it is not an ACL, so pick a path under your own
user profile.

Pipe to `jq`:

```sh
slacktokens -tokens | jq 'keys'
slacktokens -cookie | jq -r .value
```

Use the credentials with `curl` (bash):

```sh
TOKEN=$(slacktokens -tokens | jq -r '.["https://your-workspace.slack.com"].token')
DCOOKIE=$(slacktokens -cookie | jq -r .value)
curl 'https://slack.com/api/auth.test' \
  -d "token=$TOKEN" \
  --cookie "d=$DCOOKIE"
```

PowerShell:

```powershell
$tokens = slacktokens -tokens | ConvertFrom-Json
$token  = $tokens.'https://your-workspace.slack.com'.token
$dcookie = (slacktokens -cookie | ConvertFrom-Json).value
curl.exe 'https://slack.com/api/auth.test' -d "token=$token" --cookie "d=$dcookie"
```

## MCP server

A standards-compliant [Model Context Protocol](https://modelcontextprotocol.io) server is shipped under `cmd/slacktokens-mcp/`. It exposes the library to MCP-capable clients (Claude Code, Claude Desktop, Cursor, etc.) over stdio.

```sh
go install github.com/hishamkaram/slacktokens/cmd/slacktokens-mcp@latest
```

### Secure by default — credentials never enter the AI's context

A Slack token or auth cookie is a live credential. Returning one in a tool result would drop it into the calling model's context window, its transcript, and any provider-side logs — a sensitive-information-disclosure risk. So the MCP server exposes **exactly one tool**, `slack_api_call`, and it **never hands a credential to the AI**: it injects the `xoxc` token + `d` cookie server-side, calls `slack.com`, and returns only the (redacted) response.

There is deliberately **no tool that returns or writes raw credentials**. A file written as your OS user — even mode `0600` — is readable by any tool the agent can already run as you, so it would not be a real barrier. When *you* (a human) want the credentials in a file, run the CLI yourself:

```sh
slacktokens -out creds.json   # full Result JSON, mode 0600, refuses to overwrite
```

Tools:

| Name | Returns |
| --- | --- |
| `slack_api_call` | result of a Slack Web API call made with injected credentials (credential-broker proxy) |

`slack_api_call` advertises `openWorldHint: true` (it reaches the network), `readOnlyHint: false` (it can call write methods when enabled), and `destructiveHint: false` (the curated write set is additive only). The server opts out of the `logging` capability so secrets cannot leak via `notifications/message`.

Built against the official Go SDK (`github.com/modelcontextprotocol/go-sdk@v1.6.0`) and the **MCP 2025-11-25** specification.

### Using credentials without exposing them: the Slack API proxy

`slack_api_call` lets an AI *use* your Slack session without ever seeing the credential. The AI names a `workspace` (Slack URL), a `method` (e.g. `conversations.history` or `chat.postMessage`), and its `params`; the server injects the `xoxc` token + `d` cookie **server-side**, calls `slack.com`, and returns the JSON response. The credential never enters the model context, transcript, or logs.

It is **fail-closed**:

- Only methods on a curated allowlist run. Reads (`auth.test`, `conversations.history`, `users.info`, `search.messages`, …) are always available.
- Write methods (`chat.postMessage`, `reactions.add`, `conversations.mark`) run **only** when the server is started with `SLACKTOKENS_MCP_ALLOW_WRITE=1` (exactly `1`). These are additive only — nothing that overwrites or deletes. Destructive/admin methods (`chat.update`, `chat.delete`, `conversations.archive`, `admin.*`, …) are never exposed.
- Redirects are never followed (Go would otherwise re-send the `Authorization`/`Cookie` headers to the redirect target — a header-leak/SSRF risk). The API host is derived from the workspace URL: `*.slack-gov.com` workspaces hit the GovSlack API host, everything else `slack.com`.

> Scope of protection: this tool protects the **credential**, not the **response**. The Slack JSON it returns enters the model context like any other tool output and can contain private workspace data. Treat a model with this tool as able to act in Slack with your session's authority (bounded by the allowlist and the write gate).

### Add to Claude Code

Requires the `slacktokens-mcp` binary on your `PATH` (via Homebrew or `go install` — see [Install](#install)). If it isn't on `PATH`, substitute its absolute path (e.g. `$(brew --prefix)/bin/slacktokens-mcp`, or `$(go env GOPATH)/bin/slacktokens-mcp`) for `slacktokens-mcp` below.

Register the server with the [`claude mcp add`](https://docs.claude.com/en/docs/claude-code/mcp) command. Pick the capability level you want — each is strictly additive and off by default:

```bash
# Read-only (allowlisted read methods; the safe default)
claude mcp add slacktokens -s user -- slacktokens-mcp

# Read + additive writes (chat.postMessage, reactions.add, conversations.mark)
claude mcp add slacktokens -s user \
  -e SLACKTOKENS_MCP_ALLOW_WRITE=1 \
  -- slacktokens-mcp
```

- `-s user` registers the server for **all** your projects. Use `-s project` (shared via `.mcp.json`) or `-s local` (default, current project only) to narrow the scope.
- Verify with `claude mcp get slacktokens`; it should list the environment variables you set.

**Updating the flags.** Claude Code has no in-place env edit — re-register:

```bash
claude mcp remove slacktokens -s user
claude mcp add slacktokens -s user \
  -e SLACKTOKENS_MCP_ALLOW_WRITE=1 \
  -- slacktokens-mcp
```

The server reads its configuration once at startup, so restart Claude Code (or reconnect the server from the `/mcp` menu) after changing a flag.

### Add to Claude Desktop

Edit the config file — macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`; Windows: `%APPDATA%\Claude\claude_desktop_config.json` — then restart the app:

```jsonc
{
  "mcpServers": {
    "slacktokens": {
      "command": "slacktokens-mcp",
      "env": {
        "SLACKTOKENS_MCP_ALLOW_WRITE": "1"
      }
    }
  }
}
```

Omit the `env` block for read-only. Use the binary's absolute path for `command` if it isn't on `PATH`.

### Environment variables

| Variable | Default | Effect |
| --- | --- | --- |
| `SLACKTOKENS_MCP_ALLOW_WRITE` | unset | Enables the additive write methods on `slack_api_call` (`chat.postMessage`, `reactions.add`, `conversations.mark`). |
| `SLACKTOKENS_PROFILE_DIR` | unset | Overrides Slack profile-directory discovery (trusted/test-only: opened directly). |

`SLACKTOKENS_MCP_ALLOW_WRITE` is enabled only when its value is **exactly `1`** — any other value, including padded strings such as `" 1 "`, leaves it disabled (fail-closed).

## How it works

0. **Discovery** finds Slack's profile directory without running any package manager: each candidate location (Linux native / Snap / Flatpak, macOS direct / App Store, Windows `%APPDATA%`) is opened through a pinned [`os.Root`](https://pkg.go.dev/os#Root). The anchor directory is opened first, then the profile is opened *relative* to it, so Snap's in-profile `current` symlink is followed but any symlink escaping the anchor is refused by the kernel — no hand-rolled path checks. The first valid profile wins (a stderr note is printed if more than one exists); `$SLACKTOKENS_PROFILE_DIR` overrides discovery.
1. **Tokens** are read from Slack's Chromium LevelDB localStorage; the entry whose key contains `localConfig_v2` is parsed as Chromium-encoded localStorage JSON.
2. **Cookies** are read from Slack's Chromium SQLite cookies database. The `d` and `d-s` rows for `*.slack.com` are decrypted with:
   - **macOS**: AES-128-CBC, key from PBKDF2-HMAC-SHA1 (1003 iters) of the macOS Keychain item `Slack Safe Storage` (account `Slack Key` for direct download or `Slack App Store Key` for App Store).
   - **Linux**: AES-128-CBC, key from libsecret entry `Slack Safe Storage` via D-Bus Secret Service (1 iter PBKDF2). v10 fallback uses Chromium's hardcoded `peanuts`-derived key.
   - **Windows**: AES-256-GCM, key from `%APPDATA%\Slack\Local State` (`os_crypt.encrypted_key`, base64, `DPAPI` prefix stripped, then `CryptUnprotectData`).

   For Chromium ≥ 130 (cookies-DB `meta.version >= 24`), a 32-byte SHA-256 of the host_key is prepended to the plaintext and stripped on decrypt.

No CGO is required on any platform.

## Running while Slack is open

Works whether Slack is running or quit. Every read goes through a copy: the LevelDB store and the Cookies database (plus any SQLite WAL/journal sidecars) are copied — through the pinned `os.Root`, so the copy is symlink-safe and TOCTOU-safe — into a private `0700` temp directory, and the backends open those copies. A running Slack's LevelDB lock therefore never blocks the read, and no on-disk symlink swap can redirect it. LevelDB's own recovery tolerates a torn log tail; the Cookies copy is opened `mode=ro` (not `immutable`) so a copied WAL is replayed. The LevelDB copy re-checks `CURRENT` and retries a bounded number of times if a compaction raced it.

## Testing

```sh
go test ./...                                      # unit + mock-pipeline tests; no real keychain access
SLACKTOKENS_LIVE=1 go test -tags=integration -v    # end-to-end against your machine's Slack profile
```

Live integration is opt-in: it reads your real tokens and triggers the OS keychain prompt (or DPAPI on Windows). CI runs unit tests + the mock pipeline only.

## Development

Install the toolchain and the git hooks.

macOS:

```sh
brew install lefthook golangci-lint
go install golang.org/x/vuln/cmd/govulncheck@latest
lefthook install
```

Linux:

```sh
# golangci-lint
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$(go env GOPATH)/bin" v2.11.3
# lefthook
go install github.com/evilmartians/lefthook@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
lefthook install
```

Windows (PowerShell):

```powershell
# golangci-lint
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.3
# lefthook
go install github.com/evilmartians/lefthook@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
lefthook install
```

Hooks:

- **pre-commit** runs `gofmt -l`, `go vet`, and `golangci-lint`.
- **pre-push** runs `go test -race` and `govulncheck`.

CI mirrors these checks plus a `gosec` job, plus a `lint` matrix across Linux/macOS/Windows targets, plus a `test` matrix of 2 Go versions × 3 OSes.

## License

GPL-3.0-or-later. The Python source library is GPLv3, so this port must be GPLv3 as well. See [LICENSE](./LICENSE).

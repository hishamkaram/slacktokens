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
slacktokens.ErrLocalStorageLocked   // Slack is still running
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
```

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

A Slack token or auth cookie is a live credential. Returning one in a tool result would drop it into the calling model's context window, its transcript, and any provider-side logs — a sensitive-information-disclosure risk. So the MCP server is **masked by default**:

- The four read tools return only a **masked preview** (e.g. `xoxc-2…3f9a`) — enough for a human to recognise their own credential, useless as a credential itself — plus workspace/cookie metadata.
- To hand over **real, usable credentials**, call `write_credentials_file`. It writes them to a freshly created local file readable only by your OS user (mode `0600`) and returns **only the path** — the credential values never enter the model context. The file is removed when the server stops.

The credentials file holds the same JSON as `slacktokens` with no flags — `{ "tokens": …, "cookie": …, "cookies": … }` — so you or a script can consume it directly:

```sh
TOKEN=$(jq -r '.tokens["https://your-workspace.slack.com"].token' "$CREDS_FILE")
DCOOKIE=$(jq -r '.cookie.value' "$CREDS_FILE")
curl 'https://slack.com/api/auth.test' -d "token=$TOKEN" --cookie "d=$DCOOKIE"
```

Tools:

| Name | Returns |
| --- | --- |
| `get_tokens` | per-workspace name + **masked** `xoxc-*` token preview |
| `get_cookie` | the `d` auth cookie, **masked** |
| `get_cookies` | `d` and `d-s` (when present), **masked** |
| `get_tokens_and_cookie` | masked tokens + cookies in one call |
| `write_credentials_file` | path to a `0600` JSON file holding the real credentials |

The four read tools advertise `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false`. `write_credentials_file` advertises `readOnlyHint: false` and `idempotentHint: false` (it creates a file) and is otherwise non-destructive and offline. The server opts out of the `logging` capability so secrets cannot leak via `notifications/message`.

Built against the official Go SDK (`github.com/modelcontextprotocol/go-sdk@v1.6.0`) and the **MCP 2025-11-25** specification.

> Note: file handoff keeps secrets out of the model context, transcript, and logs. An agent that *also* has shell/file-read tools can still be explicitly instructed to open the file — that is a deliberate user-directed act, not the silent exposure this design prevents.

### Opting in to raw output

If you understand the exposure and still want the read tools to inline raw `xoxc-*` tokens and cookie values (the previous behaviour), start the server with the `SLACKTOKENS_MCP_ALLOW_RAW=1` environment variable. Leaving it unset keeps every read tool masked.

### Claude Code / Claude Desktop config

```jsonc
{
  "mcpServers": {
    "slacktokens": {
      "command": "slacktokens-mcp"
    }
  }
}
```

To opt in to raw output, add the environment variable:

```jsonc
{
  "mcpServers": {
    "slacktokens": {
      "command": "slacktokens-mcp",
      "env": { "SLACKTOKENS_MCP_ALLOW_RAW": "1" }
    }
  }
}
```

(Or use the absolute path to the binary if it isn't on PATH.)

## How it works

1. **Tokens** are read from Slack's Chromium LevelDB localStorage at the OS-specific path; the entry whose key contains `localConfig_v2` is parsed as Chromium-encoded localStorage JSON.
2. **Cookies** are read from Slack's Chromium SQLite cookies database. The `d` and `d-s` rows for `*.slack.com` are decrypted with:
   - **macOS**: AES-128-CBC, key from PBKDF2-HMAC-SHA1 (1003 iters) of the macOS Keychain item `Slack Safe Storage` (account `Slack Key` for direct download or `Slack App Store Key` for App Store).
   - **Linux**: AES-128-CBC, key from libsecret entry `Slack Safe Storage` via D-Bus Secret Service (1 iter PBKDF2). v10 fallback uses Chromium's hardcoded `peanuts`-derived key.
   - **Windows**: AES-256-GCM, key from `%APPDATA%\Slack\Local State` (`os_crypt.encrypted_key`, base64, `DPAPI` prefix stripped, then `CryptUnprotectData`).

   For Chromium ≥ 130 (cookies-DB `meta.version >= 24`), a 32-byte SHA-256 of the host_key is prepended to the plaintext and stripped on decrypt.

No CGO is required on any platform.

## Running while Slack is open

Works whether Slack is running or quit. If the live LevelDB is locked, the directory is snapshot-copied to a temp location and read from there (LevelDB recovery handles partial log records, so the copy is safe to read). Cookies use SQLite `mode=ro&immutable=1` and never need a snapshot.

In the rare case the snapshot itself can't be read, `ErrLocalStorageLocked` is still returned — quit Slack and retry.

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

CI mirrors these checks plus a `gosec` job, plus a `lint` matrix across Linux/macOS/Windows targets, plus a `test` matrix of 3 Go versions × 3 OSes.

## License

GPL-3.0-or-later. The Python source library is GPLv3, so this port must be GPLv3 as well. See [LICENSE](./LICENSE).

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

```sh
go get github.com/hishamkaram/slacktokens
```

CLI:

```sh
go install github.com/hishamkaram/slacktokens/cmd/slacktokens@latest
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

Use the credentials with `curl`:

```sh
TOKEN=$(slacktokens -tokens | jq -r '.["https://your-workspace.slack.com"].token')
DCOOKIE=$(slacktokens -cookie | jq -r .value)
curl 'https://slack.com/api/auth.test' \
  -d "token=$TOKEN" \
  --cookie "d=$DCOOKIE"
```

## How it works

1. **Tokens** are read from Slack's Chromium LevelDB localStorage at the OS-specific path; the entry whose key contains `localConfig_v2` is parsed as Chromium-encoded localStorage JSON.
2. **Cookies** are read from Slack's Chromium SQLite cookies database. The `d` and `d-s` rows for `*.slack.com` are decrypted with:
   - **macOS**: AES-128-CBC, key from PBKDF2-HMAC-SHA1 (1003 iters) of the macOS Keychain item `Slack Safe Storage` (account `Slack Key` for direct download or `Slack App Store Key` for App Store).
   - **Linux**: AES-128-CBC, key from libsecret entry `Slack Safe Storage` via D-Bus Secret Service (1 iter PBKDF2). v10 fallback uses Chromium's hardcoded `peanuts`-derived key.
   - **Windows**: AES-256-GCM, key from `%APPDATA%\Slack\Local State` (`os_crypt.encrypted_key`, base64, `DPAPI` prefix stripped, then `CryptUnprotectData`).

   For Chromium ≥ 130 (cookies-DB `meta.version >= 24`), a 32-byte SHA-256 of the host_key is prepended to the plaintext and stripped on decrypt.

No CGO is required on any platform.

## Important: quit Slack first

LevelDB is single-writer; opening the store while Slack is running raises `ErrLocalStorageLocked`. Quit the desktop app before invoking. The same applies to the cookies SQLite file — Chromium holds an exclusive lock while running.

## Testing

```sh
go test ./...                                      # unit + mock-pipeline tests; no real keychain access
SLACKTOKENS_LIVE=1 go test -tags=integration -v    # end-to-end against your machine's Slack profile
```

Live integration is opt-in: it reads your real tokens and triggers the OS keychain prompt. CI runs unit tests only.

## Development

Install the toolchain and the git hooks:

```sh
brew install lefthook golangci-lint
go install golang.org/x/vuln/cmd/govulncheck@latest

lefthook install
```

Hooks:

- **pre-commit** runs `gofmt -l`, `go vet`, and `golangci-lint`.
- **pre-push** runs `go test -race` and `govulncheck`.

CI mirrors these checks plus a `gosec` job and a 2×3 matrix of Go versions across Ubuntu and macOS.

## License

GPL-3.0-or-later. The Python source library is GPLv3, so this port must be GPLv3 as well. See [LICENSE](./LICENSE).

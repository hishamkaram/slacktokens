# slacktokens

Extract personal Slack workspace tokens (`xoxc-...`) and the authentication cookies (`d`, `d-s`) from the Slack desktop app's local storage.

Go port of [hraftery/slacktokens](https://github.com/hraftery/slacktokens) (Python). Same scope, same license (GPLv3), with verified-against-current-Chromium crypto plus the test suite the original lacks.

> Not endorsed or authorised by Slack Technologies LLC.

## Status

| Platform | Library | CLI |
| --- | --- | --- |
| macOS (Intel + Apple Silicon) | ✅ | ✅ |
| Linux (libsecret) | ✅ | ✅ |
| Windows | ❌ (matches Python source — Windows uses DPAPI v20, out of scope) |

Verified against Slack 4.50 / Electron 42 / Chromium 148.

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
2. **Cookies** are read from Slack's Chromium SQLite cookies database. The `d` and `d-s` rows for `*.slack.com` are decrypted with AES-128-CBC using a key derived via PBKDF2-HMAC-SHA1 from a password stored in:
   - macOS: Keychain item `Slack Safe Storage` (account `Slack Key` for direct download or `Slack App Store Key` for App Store).
   - Linux: libsecret entry `Slack Safe Storage` (via D-Bus Secret Service).

   For Chromium ≥ 130 (cookies-DB `meta.version >= 24`), a 32-byte SHA-256 of the host_key is prepended to the plaintext and stripped on decrypt.

No CGO is required.

## Important: quit Slack first

LevelDB is single-writer; opening the store while Slack is running raises `ErrLocalStorageLocked`. Quit the desktop app before invoking.

## Testing

```sh
go test ./...                                      # unit + mock-pipeline tests; no real keychain access
SLACKTOKENS_LIVE=1 go test -tags=integration -v    # end-to-end against your machine's Slack profile
```

Live integration is opt-in: it reads your real tokens and triggers the OS keychain prompt. CI runs unit tests only.

## License

GPL-3.0-or-later. The Python source library is GPLv3, so this port must be GPLv3 as well. See [LICENSE](./LICENSE).

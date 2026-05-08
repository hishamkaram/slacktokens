//go:build integration

package slacktokens_test

import (
	"os"
	"strings"
	"testing"

	"github.com/hishamkaram/slacktokens"
)

// TestLive runs against the developer machine's actual Slack profile.
//
// To enable:
//
//	SLACKTOKENS_LIVE=1 go test -tags=integration -run TestLive -v
//
// Slack must be quit before running, since LevelDB is locked while it runs.
// The macOS Keychain or Linux libsecret prompt will appear during execution.
func TestLive(t *testing.T) {
	if os.Getenv("SLACKTOKENS_LIVE") != "1" {
		t.Skip("set SLACKTOKENS_LIVE=1 to run against the real Slack profile")
	}

	res, err := slacktokens.GetTokensAndCookie()
	if err != nil {
		t.Fatalf("GetTokensAndCookie: %v", err)
	}
	if len(res.Tokens) == 0 {
		t.Fatal("expected at least one workspace token")
	}
	for url, ws := range res.Tokens {
		if !strings.HasPrefix(ws.Token, "xoxc-") {
			t.Errorf("workspace %s: token %q lacks xoxc- prefix", url, ws.Token)
		}
		if ws.Name == "" {
			t.Errorf("workspace %s: empty name", url)
		}
	}
	if res.Cookie.Name != "d" {
		t.Errorf("cookie name: got %q want %q", res.Cookie.Name, "d")
	}
	if !strings.HasPrefix(res.Cookie.Value, "xoxd-") {
		t.Errorf("cookie value lacks xoxd- prefix: %q", res.Cookie.Value)
	}
	t.Logf("workspaces=%d cookies=%d", len(res.Tokens), len(res.Cookies))
}

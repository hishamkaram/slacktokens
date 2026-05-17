// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/syndtr/goleveldb/leveldb"

	"github.com/hishamkaram/slacktokens"
)

// connect spins up the server and a client over an in-memory transport pair.
// Returns the connected client session; the caller defers Close().
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	srv := newServer()
	srvT, cliT := mcp.NewInMemoryTransports()

	ctx := context.Background()
	if _, err := srv.Connect(ctx, srvT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, cliT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestInitialize_AdvertisesNoLoggingNoResources(t *testing.T) {
	cs := connect(t)
	res := cs.InitializeResult()
	if res == nil {
		t.Fatal("nil InitializeResult")
	}
	if res.ServerInfo.Name != "slacktokens" {
		t.Errorf("server name: %q", res.ServerInfo.Name)
	}
	// Tools capability MUST be advertised; logging/resources/prompts/sampling
	// MUST NOT — secrets must not leak via notifications/message and we have
	// no resources or prompts to expose.
	if res.Capabilities.Tools == nil {
		t.Error("tools capability not advertised")
	}
	if res.Capabilities.Logging != nil {
		t.Error("logging capability MUST NOT be advertised — would risk secret leakage")
	}
	if res.Capabilities.Resources != nil {
		t.Error("unexpected resources capability")
	}
	if res.Capabilities.Prompts != nil {
		t.Error("unexpected prompts capability")
	}
}

func TestListTools_AllToolsPresentWithProperAnnotations(t *testing.T) {
	cs := connect(t)
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	want := []string{
		"get_cookie", "get_cookies", "get_tokens", "get_tokens_and_cookie",
		"write_credentials_file",
	}
	got := make([]string, 0, len(list.Tools))
	for _, tt := range list.Tools {
		got = append(got, tt.Name)
	}
	sort.Strings(got)
	if !sliceEqual(got, want) {
		t.Fatalf("tool list mismatch:\n got %v\nwant %v", got, want)
	}
	for _, tt := range list.Tools {
		if tt.Annotations == nil {
			t.Errorf("%s: missing annotations", tt.Name)
			continue
		}
		if tt.InputSchema == nil {
			t.Errorf("%s: missing InputSchema", tt.Name)
		}
		if tt.OutputSchema == nil {
			t.Errorf("%s: missing OutputSchema (structured content compliance)", tt.Name)
		}
		if tt.Description == "" {
			t.Errorf("%s: empty description", tt.Name)
		}
		// Every tool is non-destructive and closed-world.
		if tt.Annotations.DestructiveHint == nil || *tt.Annotations.DestructiveHint {
			t.Errorf("%s: DestructiveHint must be explicitly false", tt.Name)
		}
		if tt.Annotations.OpenWorldHint == nil || *tt.Annotations.OpenWorldHint {
			t.Errorf("%s: OpenWorldHint must be explicitly false", tt.Name)
		}
		// write_credentials_file creates a file: not read-only, not idempotent.
		// The four read tools must be both.
		if tt.Name == "write_credentials_file" {
			if tt.Annotations.ReadOnlyHint {
				t.Errorf("%s: ReadOnlyHint must be false — it writes a file", tt.Name)
			}
			if tt.Annotations.IdempotentHint {
				t.Errorf("%s: IdempotentHint must be false — each call writes a fresh file", tt.Name)
			}
			continue
		}
		if !tt.Annotations.ReadOnlyHint {
			t.Errorf("%s: ReadOnlyHint must be true", tt.Name)
		}
		if !tt.Annotations.IdempotentHint {
			t.Errorf("%s: IdempotentHint must be true", tt.Name)
		}
	}
}

func TestCallTool_ReturnsIsErrorWhenLibraryFails(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("library is gated to supported OSes")
	}
	// Force the library to fail by pointing it at an empty profile dir.
	t.Setenv("SLACKTOKENS_PROFILE_DIR", t.TempDir())

	cs := connect(t)
	tools := []string{
		"get_tokens", "get_cookie", "get_cookies", "get_tokens_and_cookie",
		"write_credentials_file",
	}
	for _, name := range tools {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name})
		if err != nil {
			// Per spec, tool execution failures MUST surface as IsError:true,
			// not as a JSON-RPC error.
			t.Errorf("%s: protocol-level error: %v (should be IsError:true)", name, err)
			continue
		}
		if !res.IsError {
			t.Errorf("%s: expected IsError:true on missing profile", name)
			continue
		}
		if len(res.Content) == 0 {
			t.Errorf("%s: empty Content on error", name)
		}
		// Ensure the error text doesn't accidentally include token-like
		// patterns (defense in depth — there shouldn't be a token to leak
		// when extraction failed, but verify).
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				if containsTokenPrefix(tc.Text) {
					t.Errorf("%s: error text leaked a token prefix: %q", name, tc.Text)
				}
			}
		}
	}
}

func TestCallTool_StructuredContentMatchesOutputSchema(t *testing.T) {
	// We can't run a successful call without staging Slack data — that's
	// covered by TestGetTokens_MaskedOutput_NoLeak. Here we just verify that
	// the server's tool definitions promise outputSchema, and that on a
	// (forced) error, structuredContent is appropriately absent.
	cs := connect(t)
	t.Setenv("SLACKTOKENS_PROFILE_DIR", t.TempDir())
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_tokens"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError:true")
	}
	if res.StructuredContent != nil {
		// On error the spec doesn't require structuredContent to be empty,
		// but it shouldn't carry a partial result. Surface anything unusual.
		raw, _ := json.Marshal(res.StructuredContent)
		if string(raw) != "null" && string(raw) != "{}" {
			t.Logf("note: error result carried structuredContent: %s", raw)
		}
	}
}

func TestUnknownTool_ReturnsJSONRPCError(t *testing.T) {
	// Per spec, calling a tool that doesn't exist is a protocol-level
	// error, not a tool execution error.
	cs := connect(t)
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "does_not_exist"})
	if err == nil {
		t.Fatal("expected protocol-level error for unknown tool")
	}
}

// TestGetTokens_MaskedOutput_NoLeak stages a real LevelDB token store and
// verifies that get_tokens, by default, returns only a masked preview — the
// raw token must never appear in the tool result that flows back to the model.
func TestGetTokens_MaskedOutput_NoLeak(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("library is gated to supported OSes")
	}
	const rawToken = "xoxc-0000-1111-2222-MIDDLEsecretDONOTLEAKmiddle-9f9a"

	profile := t.TempDir()
	t.Setenv("SLACKTOKENS_PROFILE_DIR", profile)
	leveldbDir := filepath.Join(profile, "Local Storage", "leveldb")
	if err := os.MkdirAll(leveldbDir, 0o755); err != nil {
		t.Fatalf("mkdir leveldb: %v", err)
	}
	stageTokensLevelDB(t, leveldbDir,
		`{"teams":{"T1":{"url":"https://acme.slack.com","token":"`+rawToken+`","name":"Acme"}}}`)

	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "get_tokens"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("get_tokens unexpectedly errored: %+v", res.Content)
	}

	blob, _ := json.Marshal(res)
	out := string(blob)
	// The raw token — and its distinctive middle — must not appear anywhere in
	// the tool result. The masked preview keeps only a head+tail slice.
	if strings.Contains(out, rawToken) {
		t.Fatalf("masked get_tokens leaked the raw token: %s", out)
	}
	if strings.Contains(out, "MIDDLEsecretDONOTLEAKmiddle") {
		t.Fatalf("masked get_tokens leaked the token middle: %s", out)
	}
	// It should still surface the workspace and a masked preview.
	if !strings.Contains(out, "acme.slack.com") {
		t.Errorf("expected workspace URL in output: %s", out)
	}
	if !strings.Contains(out, maskSecret(rawToken)) {
		t.Errorf("expected masked preview %q in output: %s", maskSecret(rawToken), out)
	}
}

func TestMaskSecret(t *testing.T) {
	cases := []struct {
		name, in string
	}{
		{"empty", ""},
		{"short", "xoxc-123"},
		{"exactly12", "xoxc-1234567"},
		{"long", "xoxc-0000-1111-2222-SECRETMIDDLE-9f9a"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := maskSecret(c.in)
			switch {
			case c.in == "":
				if got != "" {
					t.Errorf(`maskSecret("") = %q, want ""`, got)
				}
			case len(c.in) <= 12:
				if got != "…" {
					t.Errorf("maskSecret(%q) = %q, want %q", c.in, got, "…")
				}
			default:
				if strings.Contains(got, c.in) {
					t.Errorf("maskSecret(%q) = %q leaks the whole secret", c.in, got)
				}
				if !strings.HasPrefix(got, c.in[:6]) {
					t.Errorf("maskSecret(%q) = %q: want %q prefix", c.in, got, c.in[:6])
				}
				if !strings.HasSuffix(got, c.in[len(c.in)-4:]) {
					t.Errorf("maskSecret(%q) = %q: want %q suffix", c.in, got, c.in[len(c.in)-4:])
				}
			}
		})
	}
}

func TestAllowRawFromEnv(t *testing.T) {
	cases := []struct {
		val  string
		want bool
	}{
		{"", false},
		{"0", false},
		{"false", false},
		{"no", false},
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"Yes", true},
		{"on", true},
		{" 1 ", true},
	}
	for _, c := range cases {
		t.Run("val="+c.val, func(t *testing.T) {
			t.Setenv(allowRawEnv, c.val)
			if got := allowRawFromEnv(); got != c.want {
				t.Errorf("allowRawFromEnv() with %q = %v, want %v", c.val, got, c.want)
			}
		})
	}
}

func TestToMaskedWorkspaces_RawGatedByConfig(t *testing.T) {
	const rawToken = "xoxc-0000-1111-SECRETtokenVALUE-9f9a"
	in := map[string]slacktokens.Workspace{
		"https://acme.slack.com": {Token: rawToken, Name: "Acme"},
	}

	masked := toMaskedWorkspaces(in, false)["https://acme.slack.com"]
	if masked.Token != "" {
		t.Errorf("allowRaw=false: Token must be empty, got %q", masked.Token)
	}
	if !masked.TokenPresent {
		t.Error("allowRaw=false: TokenPresent must be true")
	}
	if masked.TokenPreview == "" || strings.Contains(masked.TokenPreview, "SECRETtokenVALUE") {
		t.Errorf("allowRaw=false: bad preview %q", masked.TokenPreview)
	}

	raw := toMaskedWorkspaces(in, true)["https://acme.slack.com"]
	if raw.Token != rawToken {
		t.Errorf("allowRaw=true: Token = %q, want raw value", raw.Token)
	}
}

func TestToMaskedCookies_RawGatedByConfig(t *testing.T) {
	const rawValue = "xoxd-SECRETcookieVALUEdonotleak-9f9a"
	in := []slacktokens.Cookie{{Name: "d", Value: rawValue}}

	masked := toMaskedCookies(in, false)
	if len(masked) != 1 {
		t.Fatalf("want 1 cookie, got %d", len(masked))
	}
	if masked[0].Value != "" {
		t.Errorf("allowRaw=false: Value must be empty, got %q", masked[0].Value)
	}
	if !masked[0].Present {
		t.Error("allowRaw=false: Present must be true")
	}
	if strings.Contains(masked[0].ValuePreview, "SECRETcookieVALUEdonotleak") {
		t.Errorf("allowRaw=false: preview leaks the value: %q", masked[0].ValuePreview)
	}

	raw := toMaskedCookies(in, true)
	if raw[0].Value != rawValue {
		t.Errorf("allowRaw=true: Value = %q, want raw value", raw[0].Value)
	}
}

func TestWriteCredentialsFile(t *testing.T) {
	r := slacktokens.Result{
		Tokens: map[string]slacktokens.Workspace{
			"https://acme.slack.com": {Token: "xoxc-secret-token", Name: "Acme"},
		},
		Cookie:  slacktokens.Cookie{Name: "d", Value: "xoxd-secret-cookie"},
		Cookies: []slacktokens.Cookie{{Name: "d", Value: "xoxd-secret-cookie"}},
	}
	dir := t.TempDir()
	path, n, err := writeCredentialsFile(dir, r)
	if err != nil {
		t.Fatalf("writeCredentialsFile: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("file written outside dir: %s (want under %s)", path, dir)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat written file: %v", err)
	}
	// Unix: the file must be readable only by the owner. Windows does not
	// honour Unix permission bits, so skip the check there.
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file mode = %#o, want 0600", perm)
		}
	}

	data, err := os.ReadFile(path) // #nosec G304 -- path is from os.CreateTemp under a test TempDir.
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if n != len(data) {
		t.Errorf("reported %d bytes, file holds %d", n, len(data))
	}
	var got slacktokens.Result
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("file content is not a valid JSON Result: %v", err)
	}
	if got.Cookie.Value != "xoxd-secret-cookie" {
		t.Errorf("cookie round-trip mismatch: %+v", got.Cookie)
	}
	if got.Tokens["https://acme.slack.com"].Token != "xoxc-secret-token" {
		t.Errorf("token round-trip mismatch: %+v", got.Tokens)
	}
}

// helpers

// stageTokensLevelDB writes a Chromium-style LevelDB token store at leveldbDir
// with one localConfig_v2 entry holding configJSON.
func stageTokensLevelDB(t *testing.T, leveldbDir, configJSON string) {
	t.Helper()
	db, err := leveldb.OpenFile(leveldbDir, nil)
	if err != nil {
		t.Fatalf("open staged leveldb: %v", err)
	}
	// Chromium localStorage key shape: '_' + origin + '\x00' + format-byte +
	// key-name. The reader only requires the key to contain "localConfig_v2";
	// the value is prefixed with 0x01 (Latin-1) like Chromium writes it.
	key := append([]byte("_https://app.slack.com\x00\x01"), []byte("localConfig_v2")...)
	val := append([]byte{0x01}, []byte(configJSON)...)
	if err := db.Put(key, val, nil); err != nil {
		t.Fatalf("put staged config: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close staged leveldb: %v", err)
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// containsTokenPrefix returns true if s contains a string that looks like
// a Slack token. Used to guard against accidental leakage in error paths.
func containsTokenPrefix(s string) bool {
	for _, p := range []string{"xoxc-", "xoxd-", "xoxb-", "xoxs-"} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/slacktokens"
)

const (
	testXOXC = "xoxc-TESTtokenVALUEdonotleak-9f9a"
	testXOXD = "xoxd-TESTcookieVALUEdonotleak-9f9a"
)

func testResult() slacktokens.Result {
	return slacktokens.Result{
		Tokens: map[string]slacktokens.Workspace{
			"https://acme.slack.com": {Token: testXOXC, Name: "Acme"},
		},
		Cookie: slacktokens.Cookie{Name: "d", Value: testXOXD},
		Cookies: []slacktokens.Cookie{
			{Name: "d", Value: testXOXD},
			{Name: "d-s", Value: "123"},
		},
	}
}

func TestAllowWriteFromEnv(t *testing.T) {
	// The write gate is strict: only "1" (optionally padded) enables it. The
	// looser truthy words that allowRawFromEnv accepts must NOT enable writes.
	cases := []struct {
		val  string
		want bool
	}{
		{"", false}, {"0", false}, {"false", false}, {"no", false},
		{"true", false}, {"TRUE", false}, {"Yes", false}, {"on", false},
		{"1", true}, {" 1 ", true},
	}
	for _, c := range cases {
		t.Run("val="+c.val, func(t *testing.T) {
			t.Setenv(allowWriteEnv, c.val)
			if got := allowWriteFromEnv(); got != c.want {
				t.Errorf("allowWriteFromEnv() with %q = %v, want %v", c.val, got, c.want)
			}
		})
	}
}

func TestValidateMethod(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		allowWrite bool
		wantErr    bool
	}{
		{"read allowed", "conversations.history", false, false},
		{"read allowed when write on", "users.info", true, false},
		{"write blocked by default", "chat.postMessage", false, true},
		{"write allowed when gated", "chat.postMessage", true, false},
		{"unknown method", "files.upload", true, true},
		{"destructive excluded even when gated", "chat.delete", true, true},
		{"admin excluded even when gated", "admin.users.remove", true, true},
		{"chat.update excluded (overwrites)", "chat.update", true, true},
		{"path traversal slash", "../oauth/token", true, true},
		{"path traversal dotdot", "conversations..history", true, true},
		{"well-formed but not allowlisted", "conversations.create", true, true},
		{"single segment rejected", "auth", true, true},
		{"empty rejected", "", true, true},
		{"trailing slash rejected", "auth.test/", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateMethod(c.method, c.allowWrite)
			if (err != nil) != c.wantErr {
				t.Errorf("validateMethod(%q, %v) err = %v, wantErr %v", c.method, c.allowWrite, err, c.wantErr)
			}
		})
	}
}

func TestEncodeParams_NestedJSONStringified(t *testing.T) {
	params := map[string]any{
		"channel": "C123",
		"text":    "hello",
		"unfurl":  true,
		"count":   float64(42),
		"blocks": []any{
			map[string]any{"type": "section"},
		},
	}
	form, err := encodeParams(params)
	if err != nil {
		t.Fatalf("encodeParams: %v", err)
	}
	if form.Get("channel") != "C123" {
		t.Errorf("channel = %q", form.Get("channel"))
	}
	if form.Get("unfurl") != "true" {
		t.Errorf("unfurl = %q, want true", form.Get("unfurl"))
	}
	if form.Get("count") != "42" {
		t.Errorf("count = %q, want 42", form.Get("count"))
	}
	// blocks must be a JSON string, not Go's %v rendering.
	var decoded []map[string]any
	if err := json.Unmarshal([]byte(form.Get("blocks")), &decoded); err != nil {
		t.Fatalf("blocks not valid JSON: %q (%v)", form.Get("blocks"), err)
	}
	if len(decoded) != 1 || decoded[0]["type"] != "section" {
		t.Errorf("blocks decoded wrong: %v", decoded)
	}
}

func TestResolveWorkspace(t *testing.T) {
	tokens := map[string]slacktokens.Workspace{
		"https://acme.slack.com": {Token: "t1", Name: "Acme"},
		"https://beta.slack.com": {Token: "t2", Name: "Beta"},
	}
	t.Run("exact", func(t *testing.T) {
		u, w, err := resolveWorkspace(tokens, "https://beta.slack.com")
		if err != nil || u != "https://beta.slack.com" || w.Token != "t2" {
			t.Errorf("got (%q,%+v,%v)", u, w, err)
		}
	})
	t.Run("case-insensitive", func(t *testing.T) {
		u, _, err := resolveWorkspace(tokens, "HTTPS://ACME.SLACK.COM")
		if err != nil || u != "https://acme.slack.com" {
			t.Errorf("got (%q,%v)", u, err)
		}
	})
	t.Run("empty with multiple errors", func(t *testing.T) {
		if _, _, err := resolveWorkspace(tokens, ""); err == nil {
			t.Error("expected error when workspace omitted and multiple present")
		}
	})
	t.Run("empty with single uses it", func(t *testing.T) {
		single := map[string]slacktokens.Workspace{"https://solo.slack.com": {Token: "s"}}
		u, w, err := resolveWorkspace(single, "")
		if err != nil || u != "https://solo.slack.com" || w.Token != "s" {
			t.Errorf("got (%q,%+v,%v)", u, w, err)
		}
	})
	t.Run("not found", func(t *testing.T) {
		if _, _, err := resolveWorkspace(tokens, "https://nope.slack.com"); err == nil {
			t.Error("expected not-found error")
		}
	})
}

func TestCookieHeader(t *testing.T) {
	t.Run("d only", func(t *testing.T) {
		got := cookieHeader([]slacktokens.Cookie{{Name: "d", Value: "xoxd-abc"}})
		if got != "d=xoxd-abc" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("d and d-s", func(t *testing.T) {
		got := cookieHeader([]slacktokens.Cookie{
			{Name: "d", Value: "xoxd-abc"}, {Name: "d-s", Value: "123"},
		})
		if got != "d=xoxd-abc; d-s=123" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("no d is empty", func(t *testing.T) {
		if got := cookieHeader([]slacktokens.Cookie{{Name: "d-s", Value: "123"}}); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

// newProxyHandler builds a handlers wired to a stub Slack server and stub creds.
func newProxyHandler(t *testing.T, allowWrite bool, srv *httptest.Server) *handlers {
	t.Helper()
	return &handlers{
		cfg:        mcpConfig{allowWrite: allowWrite},
		credsFn:    func() (slacktokens.Result, error) { return testResult(), nil },
		httpClient: srv.Client(),
		baseURLStr: srv.URL + "/api/",
	}
}

func TestSlackAPICall_InjectsCredsAndReturnsResponse(t *testing.T) {
	var gotAuth, gotCookie, gotCT, gotUA, gotBody, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCookie = r.Header.Get("Cookie")
		gotCT = r.Header.Get("Content-Type")
		gotUA = r.Header.Get("User-Agent")
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"channel":"C123"}`)
	}))
	defer srv.Close()

	h := newProxyHandler(t, false, srv)
	res, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "conversations.history",
		Params:    map[string]any{"channel": "C123", "limit": float64(10)},
	})
	if err != nil {
		t.Fatalf("handler returned transport error: %v", err)
	}
	if res != nil && res.IsError {
		t.Fatalf("unexpected IsError: %+v", res.Content)
	}
	// Credentials were injected server-side.
	if gotAuth != "Bearer "+testXOXC {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotCookie != "d="+testXOXD+"; d-s=123" {
		t.Errorf("Cookie = %q", gotCookie)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if gotUA != "slacktokens-mcp/"+version {
		t.Errorf("User-Agent = %q", gotUA)
	}
	if gotPath != "/api/conversations.history" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotBody, "channel=C123") || !strings.Contains(gotBody, "limit=10") {
		t.Errorf("body = %q", gotBody)
	}
	// Output is faithful and carries no credential.
	if !out.OK || out.Status != 200 {
		t.Errorf("out = %+v", out)
	}
	if out.Workspace != "https://acme.slack.com" {
		t.Errorf("out.Workspace = %q", out.Workspace)
	}
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), testXOXC) || strings.Contains(string(blob), testXOXD) {
		t.Fatalf("output leaked a credential: %s", blob)
	}
}

func TestSlackAPICall_WriteGate(t *testing.T) {
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	// Gate closed: write method is rejected BEFORE any network call.
	h := newProxyHandler(t, false, srv)
	res, _, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "chat.postMessage",
		Params:    map[string]any{"channel": "C1", "text": "hi"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatal("expected IsError when write gate closed")
	}
	if hit {
		t.Fatal("network was contacted despite closed write gate")
	}

	// Gate open: write method reaches Slack.
	hit = false
	h = newProxyHandler(t, true, srv)
	res, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "chat.postMessage",
		Params:    map[string]any{"channel": "C1", "text": "hi"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res != nil && res.IsError {
		t.Fatalf("unexpected IsError with gate open: %+v", res.Content)
	}
	if !hit {
		t.Fatal("network was NOT contacted with write gate open")
	}
	if !out.OK {
		t.Errorf("out = %+v", out)
	}
}

func TestSlackAPICall_OKFalsePassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"ok":false,"error":"channel_not_found"}`)
	}))
	defer srv.Close()

	h := newProxyHandler(t, false, srv)
	res, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "conversations.info",
		Params:    map[string]any{"channel": "CZZZ"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// Slack-level error is NOT a tool error — the model must see it.
	if res != nil && res.IsError {
		t.Fatalf("ok:false must not be IsError: %+v", res.Content)
	}
	if out.OK {
		t.Error("out.OK should be false")
	}
	if !strings.Contains(out.Body, "channel_not_found") {
		t.Errorf("body missing slack error: %q", out.Body)
	}
}

func TestSlackAPICall_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"ok":false,"error":"ratelimited"}`)
	}))
	defer srv.Close()

	h := newProxyHandler(t, false, srv)
	res, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "conversations.history",
		Params:    map[string]any{"channel": "C1"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res != nil && res.IsError {
		t.Fatalf("429 must not be IsError: %+v", res.Content)
	}
	if out.Status != http.StatusTooManyRequests {
		t.Errorf("status = %d", out.Status)
	}
	if out.RetryAfter != "30" {
		t.Errorf("RetryAfter = %q, want 30", out.RetryAfter)
	}
}

func TestSlackAPICall_ResponseTooLargeWithheld(t *testing.T) {
	big := strings.Repeat("A", maxResponseBytes+1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, big)
	}))
	defer srv.Close()

	h := newProxyHandler(t, false, srv)
	_, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "conversations.history",
		Params:    map[string]any{"channel": "C1"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !out.Truncated {
		t.Error("expected Truncated=true")
	}
	// Oversized bodies are withheld entirely, not returned as a partial slice.
	if strings.Contains(out.Body, "AAAA") {
		t.Errorf("oversized body should be withheld, not returned: %q", out.Body[:40])
	}
	if !strings.Contains(out.Body, "response_too_large") {
		t.Errorf("expected a response_too_large notice, got %q", out.Body)
	}
	if len(out.Body) >= maxResponseBytes {
		t.Errorf("notice should be short, got %d bytes", len(out.Body))
	}
}

func TestSlackAPICall_InvalidMethodNoCreds(t *testing.T) {
	credsCalled := false
	h := &handlers{
		cfg: mcpConfig{},
		credsFn: func() (slacktokens.Result, error) {
			credsCalled = true
			return testResult(), nil
		},
	}
	res, _, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "not/a/method",
		Params:    nil,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatal("expected IsError for invalid method")
	}
	if credsCalled {
		t.Error("credentials must not be read for an invalid method")
	}
}

func TestSlackAPICall_RedactsReflectedCredential(t *testing.T) {
	// Simulate a (hypothetical) endpoint that echoes the token + cookie back.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true,"echo_token":"`+testXOXC+`","echo_cookie":"`+testXOXD+`"}`)
	}))
	defer srv.Close()

	h := newProxyHandler(t, false, srv)
	_, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "auth.test",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if strings.Contains(out.Body, testXOXC) || strings.Contains(out.Body, testXOXD) {
		t.Fatalf("reflected credential was not redacted: %q", out.Body)
	}
	if !strings.Contains(out.Body, "[REDACTED]") {
		t.Errorf("expected redaction placeholder in body: %q", out.Body)
	}
	// ok is still parsed correctly from the (raw) response.
	if !out.OK {
		t.Errorf("out.OK = false, want true")
	}
}

func TestSlackAPICall_NoFragmentWhenCredentialStraddlesCap(t *testing.T) {
	// A token begins 5 bytes before the cap and runs past it. Because an
	// oversized body is withheld (not returned truncated), no fragment can leak.
	payload := strings.Repeat("A", maxResponseBytes-5) + testXOXC + strings.Repeat("B", 200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	h := newProxyHandler(t, false, srv)
	_, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "conversations.history",
		Params:    map[string]any{"channel": "C1"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if strings.Contains(out.Body, "xoxc-") {
		t.Fatalf("a token fragment leaked: %q", out.Body)
	}
	if !out.Truncated {
		t.Error("expected Truncated=true")
	}
}

func TestSlackAPICall_RedactsJSONEscapedSlashVariant(t *testing.T) {
	// Cookie value contains '/'; the endpoint reflects it JSON-escaped (\/).
	const storedCookie = "xoxd-abc/def/ghi/jkl"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true,"echo":"xoxd-abc\/def\/ghi\/jkl"}`)
	}))
	defer srv.Close()

	h := &handlers{
		cfg: mcpConfig{},
		credsFn: func() (slacktokens.Result, error) {
			return slacktokens.Result{
				Tokens:  map[string]slacktokens.Workspace{"https://acme.slack.com": {Token: testXOXC}},
				Cookies: []slacktokens.Cookie{{Name: "d", Value: storedCookie}},
			}, nil
		},
		httpClient: srv.Client(),
		baseURLStr: srv.URL + "/api/",
	}
	_, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "auth.test",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if strings.Contains(out.Body, "def") {
		t.Fatalf("JSON-escaped-slash cookie variant not redacted: %q", out.Body)
	}
}

func TestSlackAPICall_RedactsDecodedThenSlashEscapedVariant(t *testing.T) {
	// Stored percent-encoded; endpoint reflects the DECODED value with Slack's
	// JSON slash-escaping. The slash-escape must apply to the decoded variant,
	// not only to the raw stored value.
	const storedCookie = "xoxd-a%2Fb%2Fc%2Fdddd" // decodes to xoxd-a/b/c/dddd
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true,"echo":"xoxd-a\/b\/c\/dddd"}`)
	}))
	defer srv.Close()

	h := &handlers{
		cfg: mcpConfig{},
		credsFn: func() (slacktokens.Result, error) {
			return slacktokens.Result{
				Tokens:  map[string]slacktokens.Workspace{"https://acme.slack.com": {Token: testXOXC}},
				Cookies: []slacktokens.Cookie{{Name: "d", Value: storedCookie}},
			}, nil
		},
		httpClient: srv.Client(),
		baseURLStr: srv.URL + "/api/",
	}
	_, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "auth.test",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if strings.Contains(out.Body, "dddd") {
		t.Fatalf("decoded-then-slash-escaped cookie variant not redacted: %q", out.Body)
	}
}

func TestSlackAPICall_RedactsEncodingVariant(t *testing.T) {
	const storedCookie = "xoxd-a%2Fb%2Bc" // stored percent-encoded
	const reflected = "xoxd-a/b+c"        // decoded form an endpoint might echo
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true,"echo":"`+reflected+`"}`)
	}))
	defer srv.Close()

	h := &handlers{
		cfg: mcpConfig{},
		credsFn: func() (slacktokens.Result, error) {
			return slacktokens.Result{
				Tokens:  map[string]slacktokens.Workspace{"https://acme.slack.com": {Token: testXOXC}},
				Cookies: []slacktokens.Cookie{{Name: "d", Value: storedCookie}},
			}, nil
		},
		httpClient: srv.Client(),
		baseURLStr: srv.URL + "/api/",
	}
	_, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "auth.test",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if strings.Contains(out.Body, reflected) {
		t.Fatalf("decoded cookie variant was not redacted: %q", out.Body)
	}
	if !out.OK {
		t.Errorf("out.OK = false, want true")
	}
}

func TestSlackAPICall_WorkspaceOmittedSingleWorkspace(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	// testResult has exactly one workspace, so an omitted workspace resolves it.
	h := newProxyHandler(t, false, srv)
	res, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Method: "auth.test",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res != nil && res.IsError {
		t.Fatalf("unexpected IsError: %+v", res.Content)
	}
	if out.Workspace != "https://acme.slack.com" {
		t.Errorf("resolved workspace = %q", out.Workspace)
	}
	if gotAuth != "Bearer "+testXOXC {
		t.Errorf("Authorization = %q", gotAuth)
	}
}

// TestSlackAPICall_EndToEndViaMCP exercises the tool through the MCP client,
// with a stub Slack server, proving the full wire path including structured
// output and no credential leakage in the client-visible result.
func TestSlackAPICall_EndToEndViaMCP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"team":"Acme"}`)
	}))
	defer srv.Close()

	// The production server wires slackAPICall to live credentials + the real
	// Slack host, so drive a server whose handler points at our stub instead.
	h := newProxyHandler(t, false, srv)
	mcpSrv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "v0"}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{},
	})
	mcp.AddTool(mcpSrv, &mcp.Tool{
		Name:        "slack_api_call",
		Annotations: proxyAnnotations("proxy"),
	}, h.slackAPICall)

	srvT, cliT := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := mcpSrv.Connect(ctx, srvT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, cliT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = cs.Close() }()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "slack_api_call",
		Arguments: map[string]any{
			"workspace": "https://acme.slack.com",
			"method":    "auth.test",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected IsError: %+v", res.Content)
	}
	blob, _ := json.Marshal(res)
	if strings.Contains(string(blob), testXOXC) || strings.Contains(string(blob), testXOXD) {
		t.Fatalf("MCP result leaked a credential: %s", blob)
	}
	if !strings.Contains(string(blob), `\"ok\":true`) && !strings.Contains(string(blob), `"ok":true`) {
		t.Errorf("expected slack ok:true in result: %s", blob)
	}
}

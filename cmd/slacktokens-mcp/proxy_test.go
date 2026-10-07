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
	// The write gate is strict: the value must be EXACTLY "1". Looser truthy
	// words AND padded values must NOT enable writes (fail closed).
	cases := []struct {
		val  string
		want bool
	}{
		{"", false}, {"0", false}, {"false", false}, {"no", false},
		{"true", false}, {"TRUE", false}, {"Yes", false}, {"on", false},
		{" 1 ", false}, {"1\n", false}, {"1", true},
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

// TestToolDescription_ListsAllowlistAndGateState: the description must name
// every allowlisted method (so an agent picks a valid one) and reflect the live
// gate state, so a weaker model is not left guessing method names.
func TestToolDescription_ListsAllowlistAndGateState(t *testing.T) {
	all := func() []string {
		var s []string
		for m := range readMethods {
			s = append(s, m)
		}
		for m := range writeMethods {
			s = append(s, m)
		}
		for m := range destructiveMethods {
			s = append(s, m)
		}
		return s
	}
	d := toolDescription(mcpConfig{allowWrite: true, allowDestructive: true})
	for _, m := range all() {
		if !strings.Contains(d, m) {
			t.Errorf("description missing method %q", m)
		}
	}
	if !strings.Contains(d, "WRITE [ENABLED]") || !strings.Contains(d, "DESTRUCTIVE [ENABLED]") {
		t.Errorf("both-gates description should show ENABLED; got:\n%s", d)
	}
	off := toolDescription(mcpConfig{})
	if !strings.Contains(off, "WRITE [disabled]") || !strings.Contains(off, "DESTRUCTIVE [disabled]") {
		t.Errorf("default description should show disabled; got:\n%s", off)
	}
}

func TestAllowDestructiveFromEnv(t *testing.T) {
	// Same strict exact-"1" rule as the write gate (fail closed).
	cases := []struct {
		val  string
		want bool
	}{
		{"", false}, {"0", false}, {"false", false}, {"no", false},
		{"true", false}, {"TRUE", false}, {"Yes", false}, {"on", false},
		{" 1 ", false}, {"1\n", false}, {"1", true},
	}
	for _, c := range cases {
		t.Run("val="+c.val, func(t *testing.T) {
			t.Setenv(allowDestructiveEnv, c.val)
			if got := allowDestructiveFromEnv(); got != c.want {
				t.Errorf("allowDestructiveFromEnv() with %q = %v, want %v", c.val, got, c.want)
			}
		})
	}
}

// TestProxyAnnotations_DestructiveHintHonesty: the hint must be true only when
// the tool can actually run a destructive method (both gates), so a
// destructive-only config does not overstate capability.
func TestProxyAnnotations_DestructiveHintHonesty(t *testing.T) {
	cases := []struct {
		name             string
		allowWrite       bool
		allowDestructive bool
		wantHint         bool
	}{
		{"no gates", false, false, false},
		{"write only", true, false, false},
		{"destructive only", false, true, false},
		{"both gates", true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ann := proxyAnnotations("t", c.allowWrite && c.allowDestructive)
			if ann.DestructiveHint == nil || *ann.DestructiveHint != c.wantHint {
				t.Errorf("DestructiveHint = %v, want %v", ann.DestructiveHint, c.wantHint)
			}
		})
	}
}

func TestValidateMethod(t *testing.T) {
	cases := []struct {
		name             string
		method           string
		allowWrite       bool
		allowDestructive bool
		wantErr          bool
	}{
		{"read allowed", "conversations.history", false, false, false},
		{"read allowed when write on", "users.info", true, false, false},
		{"write blocked by default", "chat.postMessage", false, false, true},
		{"write allowed when gated", "chat.postMessage", true, false, false},
		{"conversations.open allowed when write gated", "conversations.open", true, false, false},
		{"conversations.open blocked by default", "conversations.open", false, false, true},
		{"unknown method", "files.upload", true, true, true},
		{"destructive blocked by default", "chat.delete", false, false, true},
		{"destructive blocked with write only", "chat.delete", true, false, true},
		{"destructive blocked with destructive only", "chat.delete", false, true, true},
		{"destructive allowed with both gates", "chat.delete", true, true, false},
		{"chat.update allowed with both gates", "chat.update", true, true, false},
		{"chat.update blocked with write only", "chat.update", true, false, true},
		{"admin excluded even when gated", "admin.users.remove", true, true, true},
		{"path traversal slash", "../oauth/token", true, true, true},
		{"path traversal dotdot", "conversations..history", true, true, true},
		{"well-formed but not allowlisted", "conversations.create", true, true, true},
		{"single segment rejected", "auth", true, true, true},
		{"empty rejected", "", true, true, true},
		{"trailing slash rejected", "auth.test/", true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateMethod(c.method, c.allowWrite, c.allowDestructive)
			if (err != nil) != c.wantErr {
				t.Errorf("validateMethod(%q, w=%v, d=%v) err = %v, wantErr %v", c.method, c.allowWrite, c.allowDestructive, err, c.wantErr)
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
	const ws = "https://acme.slack.com"
	t.Run("d only", func(t *testing.T) {
		got, err := cookieHeader([]slacktokens.Cookie{{Name: "d", Value: "xoxd-abc"}}, ws)
		if err != nil || got != "d=xoxd-abc" {
			t.Errorf("got (%q, %v)", got, err)
		}
	})
	t.Run("d and d-s", func(t *testing.T) {
		got, err := cookieHeader([]slacktokens.Cookie{
			{Name: "d", Value: "xoxd-abc"}, {Name: "d-s", Value: "123"},
		}, ws)
		if err != nil || got != "d=xoxd-abc; d-s=123" {
			t.Errorf("got (%q, %v)", got, err)
		}
	})
	t.Run("duplicate identical d is fine", func(t *testing.T) {
		got, err := cookieHeader([]slacktokens.Cookie{
			{Name: "d", Value: "xoxd-abc"}, {Name: "d", Value: "xoxd-abc"},
		}, ws)
		if err != nil || got != "d=xoxd-abc" {
			t.Errorf("got (%q, %v)", got, err)
		}
	})
	t.Run("distinct duplicate d is ambiguous error", func(t *testing.T) {
		if _, err := cookieHeader([]slacktokens.Cookie{
			{Name: "d", Value: "xoxd-abc"}, {Name: "d", Value: "xoxd-DIFFERENT"},
		}, ws); err == nil {
			t.Error("expected ambiguity error for two distinct d cookies")
		}
	})
	t.Run("distinct duplicate d-s is ambiguous error", func(t *testing.T) {
		if _, err := cookieHeader([]slacktokens.Cookie{
			{Name: "d", Value: "xoxd-abc"},
			{Name: "d-s", Value: "123"}, {Name: "d-s", Value: "456"},
		}, ws); err == nil {
			t.Error("expected ambiguity error for two distinct d-s cookies")
		}
	})
	t.Run("no d is error", func(t *testing.T) {
		if _, err := cookieHeader([]slacktokens.Cookie{{Name: "d-s", Value: "123"}}, ws); err == nil {
			t.Error("expected error when no d cookie present")
		}
	})
	t.Run("commercial + gov accounts: picks the matching d by host", func(t *testing.T) {
		cookies := []slacktokens.Cookie{
			{Name: "d", Value: "xoxd-commercial", Host: ".slack.com"},
			{Name: "d", Value: "xoxd-gov", Host: ".slack-gov.com"},
		}
		got, err := cookieHeader(cookies, "https://acme.slack.com")
		if err != nil || got != "d=xoxd-commercial" {
			t.Errorf("commercial: got (%q, %v)", got, err)
		}
		got, err = cookieHeader(cookies, "https://agency.slack-gov.com")
		if err != nil || got != "d=xoxd-gov" {
			t.Errorf("gov: got (%q, %v)", got, err)
		}
	})
	t.Run("distinct same-host d still ambiguous", func(t *testing.T) {
		if _, err := cookieHeader([]slacktokens.Cookie{
			{Name: "d", Value: "xoxd-a", Host: ".slack.com"},
			{Name: "d", Value: "xoxd-b", Host: ".slack.com"},
		}, ws); err == nil {
			t.Error("expected ambiguity error for two distinct same-host d cookies")
		}
	})
}

// TestCollectSecrets_SkipsShortValues ensures a short cookie value (e.g. a
// numeric d-s) is not blanket-redacted, which would corrupt message `ts` fields
// and counts in a response, while long credentials are still redacted.
func TestCollectSecrets_SkipsShortValues(t *testing.T) {
	r := slacktokens.Result{
		Tokens:  map[string]slacktokens.Workspace{"https://acme.slack.com": {Token: testXOXC}},
		Cookies: []slacktokens.Cookie{{Name: "d", Value: testXOXD}, {Name: "d-s", Value: "123"}},
	}
	secrets := collectSecrets(r)
	body := `{"ok":true,"messages":[{"ts":"123.000200"}]}`
	out := redactSecrets(body, secrets)
	if out != body {
		t.Fatalf("short d-s value corrupted the response ts: %q", out)
	}
	// Sanity: a long credential IS still redacted.
	leak := redactSecrets("x "+testXOXC+" y", secrets)
	if strings.Contains(leak, testXOXC) {
		t.Fatalf("long credential was not redacted: %q", leak)
	}
}

func TestBaseURL_GovSlackDerivation(t *testing.T) {
	h := &handlers{} // no baseURLStr override → production derivation
	cases := []struct {
		ws   string
		want string
	}{
		{"https://acme.slack.com/", "https://slack.com/api/"},
		{"https://acme.slack.com", "https://slack.com/api/"},
		{"https://acme.slack-gov.com/", "https://slack-gov.com/api/"},
		{"https://TEAM.SLACK-GOV.COM", "https://slack-gov.com/api/"},
		{"", "https://slack.com/api/"},
	}
	for _, c := range cases {
		if got := h.baseURL(c.ws); got != c.want {
			t.Errorf("baseURL(%q) = %q, want %q", c.ws, got, c.want)
		}
	}
}

// TestSlackAPICall_DoesNotFollowRedirect proves the proxy never re-sends the
// credential to a redirect target (header-leak / SSRF guard).
func TestSlackAPICall_DoesNotFollowRedirect(t *testing.T) {
	var targetHit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit = true
		// If the client wrongly followed, it would leak the Authorization header here.
		if r.Header.Get("Authorization") != "" {
			t.Errorf("credential leaked to redirect target: %q", r.Header.Get("Authorization"))
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	// Use the PRODUCTION client (httpClient nil) so CheckRedirect is exercised.
	h := &handlers{
		cfg:        mcpConfig{},
		credsFn:    func() (slacktokens.Result, error) { return testResult(), nil },
		baseURLStr: redirector.URL + "/api/",
	}
	res, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com", Method: "auth.test",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res != nil && res.IsError {
		t.Fatalf("unexpected IsError: %+v", res.Content)
	}
	if targetHit {
		t.Fatal("redirect was followed — credential may have leaked")
	}
	if out.Status != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want 307 (redirect returned, not followed)", out.Status)
	}
}

// TestSlackAPICall_RedactsRetryAfter proves a reflected credential in the
// Retry-After header is scrubbed, like the body.
func TestSlackAPICall_RedactsRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", testXOXC) // malicious/echoed credential
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"ok":false,"error":"rate_limited"}`)
	}))
	defer srv.Close()

	h := newProxyHandler(t, false, srv)
	_, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com", Method: "auth.test",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if strings.Contains(out.RetryAfter, testXOXC) {
		t.Fatalf("Retry-After leaked the credential: %q", out.RetryAfter)
	}
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

func TestSlackAPICall_DeleteBlockedWithoutDestructiveGate(t *testing.T) {
	// With only the write gate open, chat.delete must be rejected before any
	// network call — the destructive gate is a required second key.
	var hit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	h := newProxyHandler(t, true, srv) // allowWrite=true, allowDestructive=false
	res, _, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "chat.delete",
		Params:    map[string]any{"channel": "C1", "ts": "123.456"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res == nil || !res.IsError {
		t.Fatal("slack_api_call must reject chat.delete without the destructive gate")
	}
	if hit {
		t.Fatal("chat.delete must not reach the network when the gate is closed")
	}
}

func TestSlackAPICall_DeleteAllowedWithBothGates(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	h := newProxyHandler(t, true, srv)
	h.cfg.allowDestructive = true // second key
	res, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
		Workspace: "https://acme.slack.com",
		Method:    "chat.delete",
		Params:    map[string]any{"channel": "C1", "ts": "1401383885.000061"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res != nil && res.IsError {
		t.Fatalf("unexpected IsError: %+v", res.Content)
	}
	if gotPath != "/api/chat.delete" {
		t.Errorf("path = %q, want /api/chat.delete", gotPath)
	}
	if !out.OK {
		t.Errorf("out.OK = false: %+v", out)
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
		InputSchema: slackAPIInputSchema(),
		Annotations: proxyAnnotations("proxy", false),
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

// TestSlackAPIInput_UnmarshalRobustness proves the tool recovers Slack method
// arguments regardless of how a harness serializes them: nested object, nested
// as a JSON string, flattened to the top level, or an empty params object.
func TestSlackAPIInput_UnmarshalRobustness(t *testing.T) {
	cases := []struct {
		name string
		json string
		want map[string]any
	}{
		{"nested object", `{"method":"search.messages","params":{"query":"from:me"}}`, map[string]any{"query": "from:me"}},
		{"params as JSON string", `{"method":"search.messages","params":"{\"query\":\"from:me\"}"}`, map[string]any{"query": "from:me"}},
		{"flattened top level", `{"method":"search.messages","query":"from:me","count":5}`, map[string]any{"query": "from:me", "count": float64(5)}},
		{"empty params plus top level", `{"method":"search.messages","params":{},"query":"x"}`, map[string]any{"query": "x"}},
		{"params wins over top level", `{"method":"chat.postMessage","params":{"text":"a"},"text":"b"}`, map[string]any{"text": "a"}},
		{"null params", `{"method":"auth.test","params":null}`, map[string]any{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var in slackAPIInput
			if err := json.Unmarshal([]byte(c.json), &in); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(in.Params) != len(c.want) {
				t.Fatalf("params = %#v, want %#v", in.Params, c.want)
			}
			for k, v := range c.want {
				if in.Params[k] != v {
					t.Errorf("params[%q] = %#v, want %#v", k, in.Params[k], v)
				}
			}
		})
	}
}

// TestSlackAPIInput_UnmarshalPreservesWorkspaceMethod: reserved keys are not
// folded into params.
func TestSlackAPIInput_UnmarshalPreservesWorkspaceMethod(t *testing.T) {
	var in slackAPIInput
	if err := json.Unmarshal([]byte(`{"workspace":"https://acme.slack.com","method":"conversations.list","params":{"limit":10}}`), &in); err != nil {
		t.Fatal(err)
	}
	if in.Workspace != "https://acme.slack.com" || in.Method != "conversations.list" {
		t.Fatalf("workspace/method lost: %+v", in)
	}
	if _, bad := in.Params["workspace"]; bad {
		t.Error("workspace leaked into params")
	}
	if _, bad := in.Params["method"]; bad {
		t.Error("method leaked into params")
	}
}

// TestSlackAPICall_EndToEnd_FlattenedArgs proves the full MCP wire path recovers
// method arguments when a harness flattens them to the top level (the observed
// Hermes "params": {} failure). If the SDK validated the schema strictly and
// dropped unknown top-level keys, Slack would receive no "query" and this fails.
func TestSlackAPICall_EndToEnd_FlattenedArgs(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotQuery = r.FormValue("query")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer srv.Close()

	h := newProxyHandler(t, false, srv)
	mcpSrv := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "v0"}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{},
	})
	mcp.AddTool(mcpSrv, &mcp.Tool{Name: "slack_api_call", InputSchema: slackAPIInputSchema(), Annotations: proxyAnnotations("proxy", false)}, h.slackAPICall)

	srvT, cliT := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := mcpSrv.Connect(ctx, srvT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "v0"}, nil)
	cs, err := client.Connect(ctx, cliT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = cs.Close() }()

	// Flattened: "query" sits at the top level, params empty — the Hermes shape.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name: "slack_api_call",
		Arguments: map[string]any{
			"workspace": "https://acme.slack.com",
			"method":    "search.messages",
			"params":    map[string]any{},
			"query":     "from:me",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected IsError: %+v", res.Content)
	}
	if gotQuery != "from:me" {
		t.Fatalf("Slack received query=%q, want from:me (flattened args not recovered)", gotQuery)
	}
}

// TestStripAuthParams: a caller-supplied token (any case) is removed so it can
// never shadow the server-injected credential; other params survive.
func TestStripAuthParams(t *testing.T) {
	in := map[string]any{"token": "xoxc-evil", "Token": "x2", " TOKEN ": "x3", "channel": "C1", "text": "hi"}
	out := stripAuthParams(in)
	for k := range out {
		if strings.EqualFold(strings.TrimSpace(k), "token") {
			t.Fatalf("auth param survived: %q", k)
		}
	}
	if out["channel"] != "C1" || out["text"] != "hi" {
		t.Fatalf("non-auth params lost: %#v", out)
	}
}

// TestSlackAPICall_EndToEnd_ParamsShapes proves the SDK schema validator (which
// runs on the wire before UnmarshalJSON) accepts params as a JSON string and as
// null — the shapes the tool advertises — not just an object.
func TestSlackAPICall_EndToEnd_ParamsShapes(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want string // expected query reaching Slack ("" = none)
	}{
		{"object", map[string]any{"method": "search.messages", "params": map[string]any{"query": "a"}}, "a"},
		{"json string", map[string]any{"method": "search.messages", "params": `{"query":"b"}`}, "b"},
		{"null params + flattened", map[string]any{"method": "search.messages", "params": nil, "query": "c"}, "c"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var gotQuery string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				gotQuery = r.FormValue("query")
				_, _ = io.WriteString(w, `{"ok":true}`)
			}))
			defer srv.Close()
			h := newProxyHandler(t, false, srv)
			s := mcp.NewServer(&mcp.Implementation{Name: "t", Version: "v0"}, &mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{}})
			mcp.AddTool(s, &mcp.Tool{Name: "slack_api_call", InputSchema: slackAPIInputSchema(), Annotations: proxyAnnotations("p", false)}, h.slackAPICall)
			st, ct := mcp.NewInMemoryTransports()
			ctx := context.Background()
			if _, err := s.Connect(ctx, st, nil); err != nil {
				t.Fatal(err)
			}
			cl := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "v0"}, nil)
			cs, err := cl.Connect(ctx, ct, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = cs.Close() }()
			args := map[string]any{"workspace": "https://acme.slack.com"}
			for k, v := range c.args {
				args[k] = v
			}
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "slack_api_call", Arguments: args})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if res.IsError {
				t.Fatalf("unexpected IsError: %+v", res.Content)
			}
			if gotQuery != c.want {
				t.Fatalf("query=%q want %q", gotQuery, c.want)
			}
		})
	}
}

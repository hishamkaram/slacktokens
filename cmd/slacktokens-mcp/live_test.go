// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
//
// Live smoke test for slack_api_call. SKIPPED by default; it requires the Slack
// desktop app to be installed and signed in on this machine. It exercises the
// real proxy path (live local credentials, real HTTP client, real slack.com)
// end-to-end, printing only non-secret fields and asserting that no credential
// leaks into the tool output.
//
// Read-only proof:
//   SLACKTOKENS_LIVE=1 go test ./cmd/slacktokens-mcp/ -run TestLiveProxy -v
//
// Add a live write (posts a message to a test channel you own):
//   SLACKTOKENS_LIVE=1 SLACKTOKENS_MCP_ALLOW_WRITE=1 \
//     SLACKTOKENS_TEST_CHANNEL=C0123456789 \
//     go test ./cmd/slacktokens-mcp/ -run TestLiveProxy -v

package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestLiveProxy(t *testing.T) {
	if os.Getenv("SLACKTOKENS_LIVE") == "" {
		t.Skip("set SLACKTOKENS_LIVE=1 to run the live proof")
	}
	// Live deps: all nil => real GetTokensAndCookie, real http client, slack.com.
	h := &handlers{cfg: mcpConfig{allowWrite: allowWriteFromEnv()}}

	// Grab the first workspace URL (non-secret) for the calls.
	r, err := h.credsResult()
	if err != nil {
		t.Fatalf("read local creds: %v", err)
	}
	var ws string
	for u := range r.Tokens {
		ws = u
		break
	}
	t.Logf("workspaces found: %d; using %q", len(r.Tokens), ws)

	check := func(method string, params map[string]any) slackAPIOutput {
		res, out, err := h.slackAPICall(context.Background(), nil, slackAPIInput{
			Workspace: ws, Method: method, Params: params,
		})
		if err != nil {
			t.Fatalf("%s: transport err: %v", method, err)
		}
		if res != nil && res.IsError {
			t.Fatalf("%s: IsError: %+v", method, res.Content)
		}
		blob, _ := json.Marshal(out)
		for _, w := range r.Tokens {
			if w.Token != "" && strings.Contains(string(blob), w.Token) {
				t.Fatalf("%s: OUTPUT LEAKED A TOKEN", method)
			}
		}
		for _, c := range r.Cookies {
			if c.Value != "" && strings.Contains(string(blob), c.Value) {
				t.Fatalf("%s: OUTPUT LEAKED A COOKIE", method)
			}
		}
		return out
	}

	// auth.test
	out := check("auth.test", nil)
	var at struct {
		OK   bool   `json:"ok"`
		Team string `json:"team"`
		User string `json:"user"`
		URL  string `json:"url"`
	}
	_ = json.Unmarshal([]byte(out.Body), &at)
	t.Logf("auth.test -> status=%d ok=%v team=%q user=%q url=%q", out.Status, out.OK, at.Team, at.User, at.URL)
	if !out.OK {
		t.Fatalf("auth.test ok=false: %s", out.Body)
	}

	// conversations.list (read)
	out = check("conversations.list", map[string]any{"limit": float64(3), "exclude_archived": true})
	var cl struct {
		OK       bool `json:"ok"`
		Channels []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"channels"`
	}
	_ = json.Unmarshal([]byte(out.Body), &cl)
	t.Logf("conversations.list -> status=%d ok=%v channels_returned=%d", out.Status, out.OK, len(cl.Channels))
	if !out.OK {
		t.Fatalf("conversations.list ok=false: %s", out.Body)
	}

	// Gate proof: write method blocked when SLACKTOKENS_MCP_ALLOW_WRITE unset.
	if !allowWriteFromEnv() {
		res, _, _ := h.slackAPICall(context.Background(), nil, slackAPIInput{
			Workspace: ws, Method: "chat.postMessage",
			Params: map[string]any{"channel": "X", "text": "y"},
		})
		if res == nil || !res.IsError {
			t.Fatal("write method should be blocked without the gate")
		}
		t.Log("write gate (closed): chat.postMessage correctly rejected, no network call")
	}

	// Optional live write proof: set SLACKTOKENS_MCP_ALLOW_WRITE=1 and
	// SLACKTOKENS_TEST_CHANNEL=C....
	if allowWriteFromEnv() {
		ch := os.Getenv("SLACKTOKENS_TEST_CHANNEL")
		if ch == "" {
			t.Log("ALLOW_WRITE set but SLACKTOKENS_TEST_CHANNEL empty — skipping live post")
		} else {
			out = check("chat.postMessage", map[string]any{
				"channel": ch,
				"text":    "slacktokens-mcp proxy live test ✅",
			})
			t.Logf("chat.postMessage -> status=%d ok=%v", out.Status, out.OK)
			if !out.OK {
				t.Fatalf("chat.postMessage ok=false: %s", out.Body)
			}
		}
	}
}

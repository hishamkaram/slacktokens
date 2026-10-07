// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package main

import (
	"context"
	"encoding/json"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connect spins up the server and a client over an in-memory transport pair.
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

// TestListTools_OnlyProxyNoCredentialTools is the security contract: the server
// exposes ONLY slack_api_call (which keeps credentials server-side) and no tool
// that returns or writes raw credentials.
func TestListTools_OnlyProxyNoCredentialTools(t *testing.T) {
	cs := connect(t)
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	got := make([]string, 0, len(list.Tools))
	for _, tt := range list.Tools {
		got = append(got, tt.Name)
	}
	sort.Strings(got)
	if !sliceEqual(got, []string{"slack_api_call"}) {
		t.Fatalf("tool list must be exactly [slack_api_call], got %v", got)
	}

	// Regression guard: none of the credential-exposing tools may ever return.
	banned := map[string]bool{
		"get_tokens": true, "get_cookie": true, "get_cookies": true,
		"get_tokens_and_cookie": true, "write_credentials_file": true,
		"slack_delete_message": true,
	}
	for _, n := range got {
		if banned[n] {
			t.Fatalf("credential-exposing tool %q must not be registered", n)
		}
	}

	for _, tt := range list.Tools {
		if tt.Name != "slack_api_call" {
			continue
		}
		if tt.Annotations == nil || tt.InputSchema == nil || tt.OutputSchema == nil || tt.Description == "" {
			t.Errorf("slack_api_call: incomplete tool definition")
		}
		if tt.Annotations.OpenWorldHint == nil || !*tt.Annotations.OpenWorldHint {
			t.Errorf("slack_api_call: OpenWorldHint must be true")
		}
		if tt.Annotations.ReadOnlyHint {
			t.Errorf("slack_api_call: ReadOnlyHint must be false")
		}
		if tt.Annotations.DestructiveHint == nil || *tt.Annotations.DestructiveHint {
			t.Errorf("slack_api_call: DestructiveHint must be explicitly false")
		}
	}
}

// TestListTools_WriteGateAddsNoCredentialTool verifies that enabling the write
// gate still exposes only slack_api_call (no separate delete tool anymore).
func TestListTools_WriteGateAddsNoCredentialTool(t *testing.T) {
	t.Setenv("SLACKTOKENS_MCP_ALLOW_WRITE", "1")
	t.Setenv("SLACKTOKENS_MCP_ALLOW_DESTRUCTIVE", "1")
	cs := connect(t)
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(list.Tools) != 1 || list.Tools[0].Name != "slack_api_call" {
		names := make([]string, len(list.Tools))
		for i, tt := range list.Tools {
			names[i] = tt.Name
		}
		t.Fatalf("even with both gates, only slack_api_call should exist; got %v", names)
	}
}

// TestSlackAPICall_ReturnsIsErrorWhenCredsMissing checks the proxy surfaces a
// library failure as IsError (not a protocol error) and never leaks a token.
func TestSlackAPICall_ReturnsIsErrorWhenCredsMissing(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("library is gated to supported OSes")
	}
	t.Setenv("SLACKTOKENS_PROFILE_DIR", t.TempDir()) // empty → extraction fails

	cs := connect(t)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "slack_api_call",
		Arguments: map[string]any{"method": "auth.test"},
	})
	if err != nil {
		t.Fatalf("protocol-level error: %v (should be IsError:true)", err)
	}
	if !res.IsError {
		t.Fatal("expected IsError:true when credentials are unavailable")
	}
	blob, _ := json.Marshal(res)
	if containsTokenPrefix(string(blob)) {
		t.Fatalf("error result leaked a token prefix: %s", blob)
	}
}

func TestUnknownTool_ReturnsJSONRPCError(t *testing.T) {
	cs := connect(t)
	_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "does_not_exist"})
	if err == nil {
		t.Fatal("expected protocol-level error for unknown tool")
	}
}

// helpers

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

// containsTokenPrefix returns true if s contains a string that looks like a
// Slack token — a guard against accidental leakage in error paths.
func containsTokenPrefix(s string) bool {
	for _, p := range []string{"xoxc-", "xoxd-", "xoxb-", "xoxs-"} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

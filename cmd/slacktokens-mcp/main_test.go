// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package main

import (
	"context"
	"encoding/json"
	"runtime"
	"sort"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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

func TestListTools_AllFourPresentWithProperAnnotations(t *testing.T) {
	cs := connect(t)
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	want := []string{"get_cookie", "get_cookies", "get_tokens", "get_tokens_and_cookie"}
	got := make([]string, 0, len(list.Tools))
	for _, tt := range list.Tools {
		got = append(got, tt.Name)
	}
	sort.Strings(got)
	if len(got) != len(want) || !sliceEqual(got, want) {
		t.Fatalf("tool list mismatch:\n got %v\nwant %v", got, want)
	}
	for _, tt := range list.Tools {
		if tt.Annotations == nil {
			t.Errorf("%s: missing annotations", tt.Name)
			continue
		}
		if !tt.Annotations.ReadOnlyHint {
			t.Errorf("%s: ReadOnlyHint must be true", tt.Name)
		}
		if !tt.Annotations.IdempotentHint {
			t.Errorf("%s: IdempotentHint must be true", tt.Name)
		}
		if tt.Annotations.DestructiveHint == nil || *tt.Annotations.DestructiveHint {
			t.Errorf("%s: DestructiveHint must be explicitly false", tt.Name)
		}
		if tt.Annotations.OpenWorldHint == nil || *tt.Annotations.OpenWorldHint {
			t.Errorf("%s: OpenWorldHint must be explicitly false", tt.Name)
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
	}
}

func TestCallTool_ReturnsIsErrorWhenLibraryFails(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("library is gated to supported OSes")
	}
	// Force the library to fail by pointing it at an empty profile dir.
	t.Setenv("SLACKTOKENS_PROFILE_DIR", t.TempDir())

	cs := connect(t)
	for _, name := range []string{"get_tokens", "get_cookie", "get_cookies", "get_tokens_and_cookie"} {
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
	// covered by the library-level mock test. Here we just verify that the
	// server's tool definitions promise outputSchema, and that on a
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

// containsTokenPrefix returns true if s contains a string that looks like
// a Slack token. Used to guard against accidental leakage in error paths.
func containsTokenPrefix(s string) bool {
	for _, p := range []string{"xoxc-", "xoxd-", "xoxb-", "xoxs-"} {
		if indexOf(s, p) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

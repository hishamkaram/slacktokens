// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

// Command slacktokens-mcp is a Model Context Protocol (MCP) server that
// exposes the slacktokens library as four read-only tools, suitable for
// being launched by an MCP-capable client (Claude Code, Claude Desktop,
// Cursor, etc.) over the stdio transport.
//
// The server complies with the 2025-11-25 MCP specification:
//
//   - JSON-RPC 2.0 framing handled by the official Go SDK.
//   - Stdio transport only — no HTTP surface, no Origin checks needed.
//   - Tools advertise read-only / non-destructive / idempotent / closed-world.
//   - Output uses outputSchema + structuredContent + a TextContent fallback,
//     emitted automatically by the typed-output form of mcp.AddTool.
//   - The `logging` capability is NOT advertised, so secrets cannot leak via
//     `notifications/message`. Diagnostic logs go to stderr only.
//
// SECURITY: every tool returns Slack credentials. The descriptions are
// deliberately written to be "scary" so an MCP client surfaces the
// sensitivity to the user before invoking. Do not expose this server over
// HTTP, network, or any non-stdio transport.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/slacktokens"
)

// version is overridden at build time via -ldflags '-X main.version=...'.
// Falls back to "dev" for unreleased builds.
var version = "dev"

// Per-tool I/O types. Empty input structs intentionally have no fields —
// these tools take no parameters.
type (
	noArgs struct{}

	tokensOutput struct {
		Tokens map[string]workspace `json:"tokens" jsonschema:"map keyed by Slack workspace URL"`
	}

	workspace struct {
		Token string `json:"token" jsonschema:"the xoxc-* workspace token"`
		Name  string `json:"name"  jsonschema:"workspace display name"`
	}

	cookieOutput struct {
		Cookie cookie `json:"cookie" jsonschema:"the d cookie"`
	}

	cookiesOutput struct {
		Cookies []cookie `json:"cookies" jsonschema:"all relevant Slack auth cookies (d, d-s)"`
	}

	cookie struct {
		Name  string `json:"name"  jsonschema:"cookie name"`
		Value string `json:"value" jsonschema:"decrypted cookie value"`
	}

	tokensAndCookieOutput struct {
		Tokens  map[string]workspace `json:"tokens"`
		Cookie  cookie               `json:"cookie"  jsonschema:"the d cookie (parity with the Python source library)"`
		Cookies []cookie             `json:"cookies" jsonschema:"all auth cookies (d, d-s) when present"`
	}
)

// errorResult turns a library error into the spec-compliant tool failure
// shape: a CallToolResult with IsError:true and a single TextContent block.
// Per the MCP 2025-11-25 spec, JSON-RPC errors are reserved for protocol
// problems; tool execution failures must be reported via isError.
func errorResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			&mcp.TextContent{Text: "slacktokens: " + err.Error()},
		},
	}
}

// emptyTokens / emptyCookies build non-nil zero values of each output type so
// the SDK's outputSchema validation passes even on the error path. Returning
// IsError:true alongside an "empty but valid" structured payload is the
// idiomatic shape for the typed-output form of mcp.AddTool.
func emptyTokens() tokensOutput   { return tokensOutput{Tokens: map[string]workspace{}} }
func emptyCookies() cookiesOutput { return cookiesOutput{Cookies: []cookie{}} }
func emptyTokensAndCookie() tokensAndCookieOutput {
	return tokensAndCookieOutput{
		Tokens:  map[string]workspace{},
		Cookies: []cookie{},
	}
}

func toMapWorkspace(in map[string]slacktokens.Workspace) map[string]workspace {
	out := make(map[string]workspace, len(in))
	for k, v := range in {
		out[k] = workspace{Token: v.Token, Name: v.Name}
	}
	return out
}

func toCookieList(in []slacktokens.Cookie) []cookie {
	out := make([]cookie, len(in))
	for i, c := range in {
		out[i] = cookie{Name: c.Name, Value: c.Value}
	}
	return out
}

func handleGetTokens(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, tokensOutput, error) {
	t, err := slacktokens.GetTokens()
	if err != nil {
		return errorResult(err), emptyTokens(), nil
	}
	return nil, tokensOutput{Tokens: toMapWorkspace(t)}, nil
}

func handleGetCookie(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, cookieOutput, error) {
	c, err := slacktokens.GetCookie()
	if err != nil {
		return errorResult(err), cookieOutput{}, nil
	}
	return nil, cookieOutput{Cookie: cookie{Name: c.Name, Value: c.Value}}, nil
}

func handleGetCookies(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, cookiesOutput, error) {
	cs, err := slacktokens.GetCookies()
	if err != nil {
		return errorResult(err), emptyCookies(), nil
	}
	return nil, cookiesOutput{Cookies: toCookieList(cs)}, nil
}

func handleGetTokensAndCookie(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, tokensAndCookieOutput, error) {
	r, err := slacktokens.GetTokensAndCookie()
	if err != nil {
		return errorResult(err), emptyTokensAndCookie(), nil
	}
	return nil, tokensAndCookieOutput{
		Tokens:  toMapWorkspace(r.Tokens),
		Cookie:  cookie{Name: r.Cookie.Name, Value: r.Cookie.Value},
		Cookies: toCookieList(r.Cookies),
	}, nil
}

// readOnlyAnnotations is shared across every tool — they all read local
// Slack files, none mutate state, none touch the network, and repeated
// calls within a Slack session return the same values.
func readOnlyAnnotations(title string) *mcp.ToolAnnotations {
	falsePtr := false
	return &mcp.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    true,
		DestructiveHint: &falsePtr,
		IdempotentHint:  true,
		OpenWorldHint:   &falsePtr,
	}
}

func newServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:       "slacktokens",
		Title:      "Slack Tokens",
		Version:    version,
		WebsiteURL: "https://github.com/hishamkaram/slacktokens",
	}, &mcp.ServerOptions{
		// MUST opt out of the SDK's historical default of advertising the
		// `logging` capability. We never want to emit notifications/message
		// because tool inputs/outputs may carry Slack secrets and any log
		// frame would carry them out of process.
		Capabilities: &mcp.ServerCapabilities{},
	})

	const sensitivityNote = " SENSITIVE: returns Slack credentials that grant " +
		"full workspace access. Only invoke when the user has explicitly " +
		"asked for Slack auth material. Read-only and offline — does not " +
		"modify any state or make network calls."

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_tokens",
		Title:       "Get Slack workspace tokens (sensitive)",
		Description: "Returns the xoxc-* personal token and display name for every Slack workspace this user is logged into in the local Slack desktop app." + sensitivityNote,
		Annotations: readOnlyAnnotations("Get Slack workspace tokens (sensitive)"),
	}, handleGetTokens)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_cookie",
		Title:       "Get Slack 'd' auth cookie (sensitive)",
		Description: "Returns the 'd' authentication cookie used by Slack alongside workspace tokens. Parity with the Python source library." + sensitivityNote,
		Annotations: readOnlyAnnotations("Get Slack 'd' auth cookie (sensitive)"),
	}, handleGetCookie)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_cookies",
		Title:       "Get all Slack auth cookies (sensitive)",
		Description: "Returns every Slack authentication cookie (`d` always, `d-s` when present). Some Slack endpoints require `d-s` in addition to `d`." + sensitivityNote,
		Annotations: readOnlyAnnotations("Get all Slack auth cookies (sensitive)"),
	}, handleGetCookies)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_tokens_and_cookie",
		Title:       "Get Slack tokens + cookies in one call (sensitive)",
		Description: "Returns workspace tokens AND the auth cookies in a single call. Convenience wrapper combining `get_tokens` and `get_cookies`." + sensitivityNote,
		Annotations: readOnlyAnnotations("Get Slack tokens + cookies in one call (sensitive)"),
	}, handleGetTokensAndCookie)

	return server
}

func main() {
	// Diagnostic log goes to stderr; clients SHOULD NOT treat stderr as an
	// error indication per the MCP spec. Crucially, the `logging` capability
	// is NOT advertised, so we never emit `notifications/message` over the
	// transport — secrets can't leak that way.
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	log.SetPrefix("slacktokens-mcp: ")

	if err := newServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintln(os.Stderr, "slacktokens-mcp:", err)
		os.Exit(1)
	}
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

// Command slacktokens-mcp is a Model Context Protocol (MCP) server that exposes
// the Slack Web API to an MCP-capable client (Claude Code, Claude Desktop,
// Cursor, etc.) over the stdio transport — WITHOUT ever placing a Slack
// credential in the model's context.
//
// The server complies with the 2025-11-25 MCP specification:
//
//   - JSON-RPC 2.0 framing handled by the official Go SDK.
//   - Stdio transport only — no HTTP surface, no Origin checks needed.
//   - Output uses outputSchema + structuredContent + a TextContent fallback.
//   - The `logging` capability is NOT advertised, so secrets cannot leak via
//     `notifications/message`. Diagnostic logs go to stderr only.
//
// SECURITY: a Slack token or auth cookie is a live credential. This server
// exposes exactly ONE tool, slack_api_call: a credential-broker proxy. It
// injects the live credentials server-side, calls slack.com, and returns the
// (redacted) response — so the credential never enters the model context. It is
// fail-closed: only allowlisted methods run, and write methods require
// SLACKTOKENS_MCP_ALLOW_WRITE=1. See proxy.go.
//
// There is deliberately NO tool that returns or writes raw credentials: a file
// written as the current user (even mode 0600) is readable by any host tool
// running as that user, so it would not be a real barrier against the model.
// Humans who need the credentials in a file run the `slacktokens` CLI
// (`slacktokens -out <file>`) themselves.
//
// Do not expose this server over HTTP, network, or any non-stdio transport.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/slacktokens"
)

// version is overridden at build time via -ldflags '-X main.version=...'.
// Falls back to "dev" for unreleased builds.
var version = "dev"

// mcpConfig holds runtime configuration resolved once at startup.
type mcpConfig struct {
	// allowWrite, when true, lets the slack_api_call proxy invoke the curated
	// WRITE method set. Sourced from SLACKTOKENS_MCP_ALLOW_WRITE; default false.
	allowWrite bool
}

// handlers carries the dependencies shared by every tool handler.
type handlers struct {
	cfg mcpConfig

	// Proxy dependencies for slack_api_call. All are nil in production, where
	// the methods on *handlers fall back to live defaults (local credentials,
	// a real HTTP client, the Slack host). Tests inject stubs here.
	credsFn    func() (slacktokens.Result, error)
	httpClient *http.Client
	baseURLStr string
}

// errorResult turns a library error into the spec-compliant tool failure shape:
// a CallToolResult with IsError:true and a single TextContent block. Per the MCP
// 2025-11-25 spec, JSON-RPC errors are reserved for protocol problems; tool
// execution failures must be reported via isError.
func errorResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			&mcp.TextContent{Text: "slacktokens: " + err.Error()},
		},
	}
}

// proxyAnnotations is for slack_api_call. It reaches the network
// (OpenWorldHint=true) and can mutate remote state when the write gate is open
// (ReadOnlyHint=false). The curated write set is additive only, so it is still
// non-destructive. Each call is a fresh network request, so it is not idempotent.
func proxyAnnotations(title string) *mcp.ToolAnnotations {
	falsePtr := false
	truePtr := true
	return &mcp.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    false,
		DestructiveHint: &falsePtr,
		IdempotentHint:  false,
		OpenWorldHint:   &truePtr,
	}
}

// newServer builds the MCP server with configuration resolved from the
// environment. Use newServerWithConfig in tests to drive a specific config.
func newServer() *mcp.Server {
	return newServerWithConfig(mcpConfig{allowWrite: allowWriteFromEnv()})
}

// newServerWithConfig builds the MCP server for a specific config.
func newServerWithConfig(cfg mcpConfig) *mcp.Server {
	h := &handlers{cfg: cfg}

	server := mcp.NewServer(&mcp.Implementation{
		Name:       "slacktokens",
		Title:      "Slack Tokens",
		Version:    version,
		WebsiteURL: "https://github.com/hishamkaram/slacktokens",
	}, &mcp.ServerOptions{
		// MUST opt out of the SDK's historical default of advertising the
		// `logging` capability. We never want to emit notifications/message
		// because tool inputs/outputs may carry Slack data and any log frame
		// would carry it out of process.
		Capabilities: &mcp.ServerCapabilities{},
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:  "slack_api_call",
		Title: "Call the Slack Web API via credential proxy",
		Description: "Calls a Slack Web API method on your behalf, injecting your " +
			"Slack credentials server-side so they NEVER enter the AI's context. " +
			"Give a `workspace` (Slack URL), a `method` (e.g. conversations.history " +
			"or chat.postMessage), and its `params`. Only allowlisted methods are " +
			"permitted; write methods require the server to be started with " +
			"SLACKTOKENS_MCP_ALLOW_WRITE=1. IMPORTANT: this tool is ONLINE (it " +
			"contacts slack.com) and the Slack response is returned to the AI — the " +
			"credential is protected, but the response data is not, and some " +
			"responses contain private workspace information.",
		Annotations: proxyAnnotations("Call the Slack Web API via credential proxy"),
	}, h.slackAPICall)

	return server
}

func main() {
	// Diagnostic log goes to stderr; clients SHOULD NOT treat stderr as an error
	// indication per the MCP spec. Crucially, the `logging` capability is NOT
	// advertised, so we never emit `notifications/message` over the transport.
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	log.SetPrefix("slacktokens-mcp: ")

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "slacktokens-mcp:", err)
		os.Exit(1)
	}
}

// run serves the MCP server until the transport closes or the process is
// signalled.
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := newServerWithConfig(mcpConfig{allowWrite: allowWriteFromEnv()})

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

// Command slacktokens-mcp is a Model Context Protocol (MCP) server that
// exposes the slacktokens library to an MCP-capable client (Claude Code,
// Claude Desktop, Cursor, etc.) over the stdio transport.
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
// SECURITY: a Slack token or auth cookie is a live credential. Returning one
// in a tool result would place it in the calling model's context window, its
// transcript, and any provider-side logs — a sensitive-information-disclosure
// risk. Therefore:
//
//   - The four read tools (get_tokens, get_cookie, get_cookies,
//     get_tokens_and_cookie) return only MASKED previews by default. The
//     preview is enough for a human to recognise their credential but is not
//     itself usable.
//   - To obtain real, usable credentials, call write_credentials_file: it
//     writes them to a local file readable only by the current OS user (mode
//     0600) and returns ONLY the path. The credential values never enter the
//     model context.
//   - Setting the env var SLACKTOKENS_MCP_ALLOW_RAW=1 is a deliberate,
//     documented opt-out that inlines raw values into the read tools again.
//
// Do not expose this server over HTTP, network, or any non-stdio transport.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

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
		Tokens map[string]maskedWorkspace `json:"tokens" jsonschema:"map keyed by Slack workspace URL"`
	}

	// maskedWorkspace describes one workspace. Token carries the raw xoxc-*
	// value only when the server runs with SLACKTOKENS_MCP_ALLOW_RAW enabled;
	// otherwise only the masked TokenPreview is populated.
	maskedWorkspace struct {
		Name         string `json:"name"          jsonschema:"workspace display name"`
		TokenPreview string `json:"token_preview" jsonschema:"masked token preview (e.g. xoxc-2…3f9a) — for human verification only, NOT a usable credential"`
		TokenPresent bool   `json:"token_present" jsonschema:"true when a non-empty token was found"`
		Token        string `json:"token,omitempty" jsonschema:"raw xoxc-* token; populated ONLY when the server is started with SLACKTOKENS_MCP_ALLOW_RAW enabled"`
	}

	cookieOutput struct {
		Cookie maskedCookie `json:"cookie" jsonschema:"the d cookie, masked"`
	}

	cookiesOutput struct {
		Cookies []maskedCookie `json:"cookies" jsonschema:"all relevant Slack auth cookies (d, d-s), masked"`
	}

	// maskedCookie describes one auth cookie. Value carries the raw cookie
	// value only when the server runs with SLACKTOKENS_MCP_ALLOW_RAW enabled.
	maskedCookie struct {
		Name         string `json:"name"          jsonschema:"cookie name"`
		ValuePreview string `json:"value_preview" jsonschema:"masked cookie value — for human verification only, NOT a usable credential"`
		Present      bool   `json:"present"       jsonschema:"true when a non-empty value was found"`
		Value        string `json:"value,omitempty" jsonschema:"raw cookie value; populated ONLY when the server is started with SLACKTOKENS_MCP_ALLOW_RAW enabled"`
	}

	tokensAndCookieOutput struct {
		Tokens  map[string]maskedWorkspace `json:"tokens"`
		Cookie  maskedCookie               `json:"cookie"  jsonschema:"the d cookie, masked (parity with the Python source library)"`
		Cookies []maskedCookie             `json:"cookies" jsonschema:"all auth cookies (d, d-s) when present, masked"`
	}

	// writeCredsOutput is the result of write_credentials_file. It deliberately
	// carries no credential values — only the path to the file that holds them.
	writeCredsOutput struct {
		Path           string `json:"path"            jsonschema:"absolute path to a newly created 0600-mode JSON file containing the live credentials"`
		Mode           string `json:"mode"            jsonschema:"file permission bits (octal) — readable only by the current OS user"`
		Bytes          int    `json:"bytes"           jsonschema:"size of the written file in bytes"`
		WorkspaceCount int    `json:"workspace_count" jsonschema:"number of Slack workspaces written to the file"`
		CookieCount    int    `json:"cookie_count"    jsonschema:"number of auth cookies written to the file"`
		Note           string `json:"note"            jsonschema:"handling guidance for the caller"`
	}
)

// mcpConfig holds runtime configuration resolved once at startup.
type mcpConfig struct {
	// allowRaw, when true, makes the read tools inline raw credential values.
	// Sourced from SLACKTOKENS_MCP_ALLOW_RAW; default false (masked).
	allowRaw bool
}

// credStore lazily creates a private, per-process directory (mode 0700) that
// holds the credential files written by write_credentials_file. cleanup
// removes the whole directory; call it on shutdown so credential files never
// outlive the server.
type credStore struct {
	once sync.Once
	dir  string
	err  error
}

func (cs *credStore) dirPath() (string, error) {
	cs.once.Do(func() {
		cs.dir, cs.err = os.MkdirTemp("", "slacktokens-mcp-")
	})
	return cs.dir, cs.err
}

func (cs *credStore) cleanup() {
	if cs.dir != "" {
		_ = os.RemoveAll(cs.dir)
	}
}

// handlers carries the dependencies shared by every tool handler.
type handlers struct {
	cfg   mcpConfig
	store *credStore
}

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
func emptyTokens() tokensOutput   { return tokensOutput{Tokens: map[string]maskedWorkspace{}} }
func emptyCookies() cookiesOutput { return cookiesOutput{Cookies: []maskedCookie{}} }
func emptyTokensAndCookie() tokensAndCookieOutput {
	return tokensAndCookieOutput{
		Tokens:  map[string]maskedWorkspace{},
		Cookies: []maskedCookie{},
	}
}

func (h *handlers) getTokens(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, tokensOutput, error) {
	t, err := slacktokens.GetTokens()
	if err != nil {
		return errorResult(err), emptyTokens(), nil
	}
	return nil, tokensOutput{Tokens: toMaskedWorkspaces(t, h.cfg.allowRaw)}, nil
}

func (h *handlers) getCookie(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, cookieOutput, error) {
	c, err := slacktokens.GetCookie()
	if err != nil {
		return errorResult(err), cookieOutput{}, nil
	}
	return nil, cookieOutput{Cookie: toMaskedCookie(c, h.cfg.allowRaw)}, nil
}

func (h *handlers) getCookies(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, cookiesOutput, error) {
	cs, err := slacktokens.GetCookies()
	if err != nil {
		return errorResult(err), emptyCookies(), nil
	}
	return nil, cookiesOutput{Cookies: toMaskedCookies(cs, h.cfg.allowRaw)}, nil
}

func (h *handlers) getTokensAndCookie(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, tokensAndCookieOutput, error) {
	r, err := slacktokens.GetTokensAndCookie()
	if err != nil {
		return errorResult(err), emptyTokensAndCookie(), nil
	}
	return nil, tokensAndCookieOutput{
		Tokens:  toMaskedWorkspaces(r.Tokens, h.cfg.allowRaw),
		Cookie:  toMaskedCookie(r.Cookie, h.cfg.allowRaw),
		Cookies: toMaskedCookies(r.Cookies, h.cfg.allowRaw),
	}, nil
}

// writeCredentials extracts the live credentials and writes them to a 0600
// file, returning only the path. The credential values never appear in the
// tool result, so they do not enter the calling model's context.
func (h *handlers) writeCredentials(_ context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, writeCredsOutput, error) {
	r, err := slacktokens.GetTokensAndCookie()
	if err != nil {
		return errorResult(err), writeCredsOutput{}, nil
	}
	dir, err := h.store.dirPath()
	if err != nil {
		return errorResult(fmt.Errorf("create credentials directory: %w", err)), writeCredsOutput{}, nil
	}
	path, n, err := writeCredentialsFile(dir, r)
	if err != nil {
		return errorResult(fmt.Errorf("write credentials file: %w", err)), writeCredsOutput{}, nil
	}
	return nil, writeCredsOutput{
		Path:           path,
		Mode:           "0600",
		Bytes:          n,
		WorkspaceCount: len(r.Tokens),
		CookieCount:    len(r.Cookies),
		Note: "This file holds live Slack credentials. It is readable only by " +
			"your OS user (mode 0600) and is deleted when this MCP server stops. " +
			"Hand the path to the user or to a script — do not open or print the " +
			"file contents here.",
	}, nil
}

// readOnlyAnnotations is shared across the four read tools — they all read
// local Slack files, none mutate state, none touch the network, and repeated
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

// writeFileAnnotations is for write_credentials_file: it creates a new file,
// so it is not read-only and not idempotent (each call writes a fresh file).
// It still destroys nothing and touches no network.
func writeFileAnnotations(title string) *mcp.ToolAnnotations {
	falsePtr := false
	return &mcp.ToolAnnotations{
		Title:           title,
		ReadOnlyHint:    false,
		DestructiveHint: &falsePtr,
		IdempotentHint:  false,
		OpenWorldHint:   &falsePtr,
	}
}

// newServer builds the MCP server with configuration resolved from the
// environment. Use newServerWithConfig in tests to drive a specific config.
func newServer() *mcp.Server {
	srv, _ := newServerWithConfig(mcpConfig{allowRaw: allowRawFromEnv()})
	return srv
}

// newServerWithConfig builds the MCP server and the credential store that
// backs write_credentials_file. The caller owns the returned store and must
// call store.cleanup() on shutdown.
func newServerWithConfig(cfg mcpConfig) (*mcp.Server, *credStore) {
	store := &credStore{}
	h := &handlers{cfg: cfg, store: store}

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

	const maskedNote = " By default this returns only a MASKED preview — never " +
		"a usable credential — so Slack secrets do not enter the AI's context " +
		"or transcript. To obtain real, usable credentials, call " +
		"write_credentials_file. Raw values are inlined here only when the " +
		"server is started with the SLACKTOKENS_MCP_ALLOW_RAW environment " +
		"variable set. Read-only and offline."

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_tokens",
		Title:       "List Slack workspace tokens (masked)",
		Description: "Lists every Slack workspace this user is signed into in the local desktop app, each with its display name and a masked token preview." + maskedNote,
		Annotations: readOnlyAnnotations("List Slack workspace tokens (masked)"),
	}, h.getTokens)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_cookie",
		Title:       "Get Slack 'd' auth cookie (masked)",
		Description: "Reports the Slack 'd' authentication cookie used alongside workspace tokens, as a masked preview. Parity with the Python source library." + maskedNote,
		Annotations: readOnlyAnnotations("Get Slack 'd' auth cookie (masked)"),
	}, h.getCookie)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_cookies",
		Title:       "Get all Slack auth cookies (masked)",
		Description: "Reports every Slack authentication cookie (`d` always, `d-s` when present) as masked previews. Some Slack endpoints require `d-s` in addition to `d`." + maskedNote,
		Annotations: readOnlyAnnotations("Get all Slack auth cookies (masked)"),
	}, h.getCookies)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_tokens_and_cookie",
		Title:       "Get Slack tokens + cookies in one call (masked)",
		Description: "Reports workspace tokens AND the auth cookies in a single call, all masked. Convenience wrapper combining `get_tokens` and `get_cookies`." + maskedNote,
		Annotations: readOnlyAnnotations("Get Slack tokens + cookies in one call (masked)"),
	}, h.getTokensAndCookie)

	mcp.AddTool(server, &mcp.Tool{
		Name:  "write_credentials_file",
		Title: "Write Slack credentials to a local file (sensitive)",
		Description: "Extracts the live Slack workspace tokens and authentication " +
			"cookies and writes them as JSON to a newly created local file " +
			"readable only by the current OS user (mode 0600). Returns ONLY the " +
			"file path plus metadata — the credential values never enter the " +
			"AI's context. Hand the returned path to the user or to a script; do " +
			"not open or print the file contents yourself. Triggers an OS " +
			"keychain / credential prompt. The file is deleted when this MCP " +
			"server stops.",
		Annotations: writeFileAnnotations("Write Slack credentials to a local file (sensitive)"),
	}, h.writeCredentials)

	return server, store
}

func main() {
	// Diagnostic log goes to stderr; clients SHOULD NOT treat stderr as an
	// error indication per the MCP spec. Crucially, the `logging` capability
	// is NOT advertised, so we never emit `notifications/message` over the
	// transport — secrets can't leak that way.
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	log.SetPrefix("slacktokens-mcp: ")

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "slacktokens-mcp:", err)
		os.Exit(1)
	}
}

// run serves the MCP server until the transport closes or the process is
// signalled. Its deferred cleanups (signal handler, credential-store removal)
// always run — main keeps os.Exit out of their way.
func run() error {
	// Cancel on SIGINT/SIGTERM so the deferred credential-store cleanup runs
	// and credential files never outlive the process.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server, store := newServerWithConfig(mcpConfig{allowRaw: allowRawFromEnv()})
	defer store.cleanup()

	if err := server.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

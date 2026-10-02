// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hishamkaram/slacktokens"
)

// slack_api_call is a CREDENTIAL-BROKER proxy: the model names a Slack Web API
// method, a workspace, and the method's params; this server injects the live
// xoxc token + d cookie server-side, calls Slack, and returns the JSON. The
// credential itself never enters the model's context — but note the Slack
// RESPONSE does, and some responses carry sensitive data. This tool protects
// the credential, not the payload.
//
// Unlike the other tools it is NOT offline: it is OpenWorldHint=true. It is
// fail-closed — only methods on a curated allowlist are permitted, and write
// methods require the operator to opt in with SLACKTOKENS_MCP_ALLOW_WRITE.

const (
	// allowWriteEnv opts in to the curated WRITE method set. Unset (default)
	// keeps the proxy read-only. Mirrors allowRawEnv in secrets.go.
	allowWriteEnv = "SLACKTOKENS_MCP_ALLOW_WRITE"

	// slackAPIBaseURL is the canonical Web API host. xoxc+d authenticates here.
	slackAPIBaseURL = "https://slack.com/api/"

	// maxResponseBytes caps how much of a Slack response flows back into the
	// model context, so a huge conversations.history can't blow up the window.
	maxResponseBytes = 256 * 1024

	// slackRequestTimeout bounds a single proxied call.
	slackRequestTimeout = 30 * time.Second
)

// readMethods are always allowed. They read state only.
var readMethods = map[string]bool{
	"auth.test":             true,
	"conversations.list":    true,
	"conversations.history": true,
	"conversations.replies": true,
	"conversations.info":    true,
	"users.info":            true,
	"users.list":            true,
	"users.conversations":   true,
	"search.messages":       true,
	"team.info":             true,
	"emoji.list":            true,
}

// writeMethods are allowed ONLY when SLACKTOKENS_MCP_ALLOW_WRITE is set. The
// set is deliberately small and ADDITIVE — no method here overwrites or removes
// existing content (chat.update is intentionally excluded because it rewrites a
// message), so DestructiveHint=false stays honest and a confused-deputy call
// cannot destroy state even with the gate open.
var writeMethods = map[string]bool{
	"chat.postMessage":   true,
	"reactions.add":      true,
	"conversations.mark": true,
}

// methodPattern constrains a method to Slack's dotted shape (segments are
// camelCase, e.g. chat.postMessage). It forbids '/', '..', leading digits and
// empty segments, so a crafted method cannot escape the /api/ path. The
// allowlist is the real authority; this is a cheap structural guard.
var methodPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$`)

// allowWriteFromEnv reports whether the operator opted in to write methods.
// The write gate is deliberately STRICT — it accepts only the documented
// value "1", not the looser truthy set that allowRawFromEnv honours, so
// enabling remote writes is always an explicit, unambiguous choice.
func allowWriteFromEnv() bool {
	return strings.TrimSpace(os.Getenv(allowWriteEnv)) == "1"
}

// slackAPIInput is the tool's input.
type slackAPIInput struct {
	Workspace string         `json:"workspace,omitempty" jsonschema:"Slack workspace URL to act as, e.g. https://acme.slack.com — selects which xoxc token to use. Omit when only one workspace is signed in."`
	Method    string         `json:"method"    jsonschema:"Slack Web API method, e.g. conversations.history or chat.postMessage. Must be on the server's allowlist."`
	Params    map[string]any `json:"params,omitempty" jsonschema:"method arguments, e.g. {\"channel\":\"C123\",\"text\":\"hi\"}. Nested values (blocks, attachments) are JSON-encoded automatically."`
}

// slackAPIOutput is the tool's result. It never contains the token or cookie.
type slackAPIOutput struct {
	OK         bool   `json:"ok"         jsonschema:"Slack's own ok flag parsed from the response (false on Slack API errors)"`
	Status     int    `json:"status"     jsonschema:"HTTP status code from Slack"`
	Workspace  string `json:"workspace"  jsonschema:"the resolved workspace URL the call was made against"`
	Method     string `json:"method"     jsonschema:"the method that was called"`
	Body       string `json:"body"       jsonschema:"the raw Slack JSON response body (possibly truncated); contains NO credential but MAY contain sensitive workspace data"`
	Truncated  bool   `json:"truncated,omitempty"   jsonschema:"true when the response exceeded the size cap and was truncated"`
	RetryAfter string `json:"retry_after,omitempty" jsonschema:"value of the Retry-After header on an HTTP 429 (seconds); the caller should wait and retry"`
}

// credsResult returns the live credentials. The default reads them from the
// local Slack app; tests inject a stub via h.credsFn.
func (h *handlers) credsResult() (slacktokens.Result, error) {
	if h.credsFn != nil {
		return h.credsFn()
	}
	return slacktokens.GetTokensAndCookie()
}

// client returns the HTTP client for proxied calls. Tests inject a stub.
func (h *handlers) client() *http.Client {
	if h.httpClient != nil {
		return h.httpClient
	}
	return &http.Client{Timeout: slackRequestTimeout}
}

// baseURL returns the Slack API base. Tests point this at an httptest server.
func (h *handlers) baseURL() string {
	if h.baseURLStr != "" {
		return h.baseURLStr
	}
	return slackAPIBaseURL
}

// validateMethod enforces the shape + allowlist, fail-closed.
func validateMethod(method string, allowWrite bool) error {
	if !methodPattern.MatchString(method) {
		return fmt.Errorf("invalid Slack method name %q", method)
	}
	if readMethods[method] {
		return nil
	}
	if writeMethods[method] {
		if !allowWrite {
			return fmt.Errorf("method %q is a write method; it is disabled — set %s=1 to enable write methods", method, allowWriteEnv)
		}
		return nil
	}
	return fmt.Errorf("method %q is not on the allowlist (read methods are always available; write methods require %s=1)", method, allowWriteEnv)
}

// encodeParams flattens params into a urlencoded form body. Scalars become
// their string form; any array/object value is JSON-encoded, as Slack's
// form-encoded endpoints expect for fields like blocks and attachments.
func encodeParams(params map[string]any) (url.Values, error) {
	v := url.Values{}
	for key, val := range params {
		switch t := val.(type) {
		case nil:
			// skip null params
		case string:
			v.Set(key, t)
		case bool:
			v.Set(key, strconv.FormatBool(t))
		case json.Number:
			v.Set(key, t.String())
		case float64:
			// JSON numbers decode to float64 through encoding/json.
			v.Set(key, strconv.FormatFloat(t, 'f', -1, 64))
		default:
			b, err := json.Marshal(t)
			if err != nil {
				return nil, fmt.Errorf("encode param %q: %w", key, err)
			}
			v.Set(key, string(b))
		}
	}
	return v, nil
}

// resolveWorkspace picks the xoxc token for the requested workspace. An exact
// (case-insensitive) match on the workspace URL wins; when workspace is empty
// and exactly one is signed in, that one is used. On failure it lists the
// available workspace URLs — those are not secrets.
func resolveWorkspace(tokens map[string]slacktokens.Workspace, workspace string) (string, slacktokens.Workspace, error) {
	if len(tokens) == 0 {
		return "", slacktokens.Workspace{}, errors.New("no Slack workspaces found")
	}
	if workspace == "" {
		if len(tokens) == 1 {
			for u, w := range tokens {
				return u, w, nil
			}
		}
		return "", slacktokens.Workspace{}, fmt.Errorf("workspace is required when multiple are signed in; available: %s", strings.Join(sortedKeys(tokens), ", "))
	}
	if w, ok := tokens[workspace]; ok {
		return workspace, w, nil
	}
	for u, w := range tokens {
		if strings.EqualFold(u, workspace) {
			return u, w, nil
		}
	}
	return "", slacktokens.Workspace{}, fmt.Errorf("workspace %q not found; available: %s", workspace, strings.Join(sortedKeys(tokens), ", "))
}

// collectSecrets returns every credential value to scrub from a response body,
// plus the encoding variants a reflecting endpoint might use: URL-decoded,
// URL-encoded, and JSON-escaped-slash forms. Variants are added only when they
// are long (>= minVariantLen) and differ from the raw value, so a degenerate
// form (e.g. url.QueryUnescape turning "+" into a space) can never blank
// ordinary response text. The raw value is always included. The list is sorted
// longest-first so a shorter variant cannot partially shadow a longer one.
func collectSecrets(r slacktokens.Result) []string {
	const minVariantLen = 8
	set := make(map[string]struct{})
	add := func(s string) {
		if s == "" {
			return
		}
		set[s] = struct{}{} // the raw value is always redacted
		variant := func(v string) {
			if len(v) >= minVariantLen && v != s {
				set[v] = struct{}{}
			}
		}
		// Base encoding forms a reflecting endpoint might use.
		bases := []string{s}
		if dec, err := url.QueryUnescape(s); err == nil {
			bases = append(bases, dec)
		}
		bases = append(bases, url.QueryEscape(s))
		// For each base form, also cover its JSON-escaped-slash rendering
		// (Go's encoding/json leaves '/' bare, but Slack emits "\/").
		for _, b := range bases {
			variant(b)
			variant(strings.ReplaceAll(b, "/", `\/`))
		}
	}
	for _, w := range r.Tokens {
		add(w.Token)
	}
	for _, c := range r.Cookies {
		add(c.Value)
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// redactSecrets replaces any occurrence of a live credential value in s with a
// placeholder. The allowlisted methods are not known to echo the token or
// cookie, but this is defense-in-depth: the Slack response flows into the model
// context, so a credential must never ride along even if an endpoint reflects
// one (or a user pasted their own token into a channel the model then reads).
func redactSecrets(s string, secrets []string) string {
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		s = strings.ReplaceAll(s, sec, "[REDACTED]")
	}
	return s
}

// cookieHeader builds the Cookie header value. The d cookie is required; d-s
// is appended only when present. Slack's d cookie is domain-wide on slack.com
// and shared across every workspace (only the xoxc token is per-workspace), so
// a single d value authenticates any workspace selection.
func cookieHeader(cookies []slacktokens.Cookie) string {
	var d, ds string
	for _, c := range cookies {
		switch c.Name {
		case "d":
			d = c.Value
		case "d-s":
			ds = c.Value
		}
	}
	if d == "" {
		return ""
	}
	h := "d=" + d
	if ds != "" {
		h += "; d-s=" + ds
	}
	return h
}

func sortedKeys(m map[string]slacktokens.Workspace) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// slackAPICall is the tool handler. Infrastructure failures (bad method, no
// creds, transport error) return IsError. A reached-Slack call — including a
// Slack-level ok:false or an HTTP 429 — is a SUCCESSFUL tool execution: the
// response is returned so the model can inspect and self-correct.
func (h *handlers) slackAPICall(ctx context.Context, _ *mcp.CallToolRequest, in slackAPIInput) (*mcp.CallToolResult, slackAPIOutput, error) {
	// 1. Validate the method first — cheap, and avoids touching credentials
	//    for a call that can never be allowed.
	if err := validateMethod(in.Method, h.cfg.allowWrite); err != nil {
		return errorResult(err), slackAPIOutput{}, nil
	}

	// 2. Resolve live credentials in-process. They never leave this function.
	r, err := h.credsResult()
	if err != nil {
		return errorResult(err), slackAPIOutput{}, nil
	}
	wsURL, ws, err := resolveWorkspace(r.Tokens, in.Workspace)
	if err != nil {
		return errorResult(err), slackAPIOutput{}, nil
	}
	if ws.Token == "" {
		return errorResult(fmt.Errorf("workspace %q has no token", wsURL)), slackAPIOutput{}, nil
	}
	cookie := cookieHeader(r.Cookies)
	if cookie == "" {
		return errorResult(errors.New("no d cookie available — cannot authenticate to Slack")), slackAPIOutput{}, nil
	}

	// 3. Build the request body.
	form, err := encodeParams(in.Params)
	if err != nil {
		return errorResult(err), slackAPIOutput{}, nil
	}

	// 4. Build and send. The URL is constrained: baseURL is a constant and
	//    method passed methodPattern + the allowlist, so it cannot escape /api/.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL()+in.Method, strings.NewReader(form.Encode())) // #nosec G107 -- method is allowlisted and regex-validated; base is a constant.
	if err != nil {
		return errorResult(fmt.Errorf("build request: %w", err)), slackAPIOutput{}, nil
	}
	req.Header.Set("Authorization", "Bearer "+ws.Token)
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "slacktokens-mcp/"+version)

	resp, err := h.client().Do(req)
	if err != nil {
		// Do not wrap req/err with headers — avoid any chance of logging creds.
		return errorResult(fmt.Errorf("slack request failed: %w", err)), slackAPIOutput{}, nil
	}
	defer func() { _ = resp.Body.Close() }()

	// 5. Read the body, bounded at the cap plus one byte to detect overflow.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return errorResult(fmt.Errorf("read slack response: %w", err)), slackAPIOutput{}, nil
	}

	out := slackAPIOutput{
		Status:    resp.StatusCode,
		Workspace: wsURL,
		Method:    in.Method,
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		out.RetryAfter = resp.Header.Get("Retry-After")
	}

	// Oversized responses are NOT returned as a truncated slice: a partial body
	// risks splitting a credential across the cut (leaving an un-redactable
	// fragment) or a UTF-8 rune, and is rarely useful. Instead return a short
	// machine-readable notice so the model narrows its request. This keeps
	// redaction operating only on COMPLETE bodies, where a credential can never
	// be split.
	if len(data) > maxResponseBytes {
		out.Truncated = true
		out.Body = fmt.Sprintf(`{"ok":false,"error":"response_too_large","detail":"Slack response exceeded %d bytes and was withheld; narrow the request (e.g. a smaller limit or use pagination/cursor)."}`, maxResponseBytes)
		return nil, out, nil
	}

	// Complete response: redact credentials (and their encoding variants) in
	// full before the body enters the model context, then parse Slack's ok flag.
	out.Body = redactSecrets(string(data), collectSecrets(r))
	var probe struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(data, &probe) == nil {
		out.OK = probe.OK
	}
	return nil, out, nil
}

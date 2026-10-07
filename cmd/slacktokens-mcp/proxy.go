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

	"github.com/google/jsonschema-go/jsonschema"
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
	// keeps the proxy read-only.
	allowWriteEnv = "SLACKTOKENS_MCP_ALLOW_WRITE"

	// allowDestructiveEnv opts in to the DESTRUCTIVE method set (chat.delete,
	// chat.update). It is a SECOND key: destructive methods run only when BOTH
	// allowWriteEnv AND allowDestructiveEnv are set. Unset (default) keeps
	// deletion/overwrite unavailable even with writes enabled.
	allowDestructiveEnv = "SLACKTOKENS_MCP_ALLOW_DESTRUCTIVE"

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
// set is ADDITIVE — nothing here overwrites or removes existing content:
// conversations.open just opens/returns a DM or group DM channel. Overwriting or
// deleting lives in destructiveMethods behind the second gate.
var writeMethods = map[string]bool{
	"chat.postMessage":   true,
	"reactions.add":      true,
	"conversations.mark": true,
	"conversations.open": true,
}

// destructiveMethods require BOTH SLACKTOKENS_MCP_ALLOW_WRITE and
// SLACKTOKENS_MCP_ALLOW_DESTRUCTIVE. chat.delete removes a message (irreversible,
// and with an admin account can remove other users' messages); chat.update
// overwrites one. Separated so the common write gate stays non-destructive.
var destructiveMethods = map[string]bool{
	"chat.delete": true,
	"chat.update": true,
}

// methodPattern constrains a method to Slack's dotted shape (segments are
// camelCase, e.g. chat.postMessage). It forbids '/', '..', leading digits and
// empty segments, so a crafted method cannot escape the /api/ path. The
// allowlist is the real authority; this is a cheap structural guard.
var methodPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$`)

// allowWriteFromEnv reports whether the operator opted in to write methods.
// The gate is deliberately STRICT — the value must be EXACTLY "1" (no
// surrounding whitespace), so an accidentally padded value fails closed and
// enabling remote writes is always an explicit, unambiguous choice.
func allowWriteFromEnv() bool {
	return os.Getenv(allowWriteEnv) == "1"
}

// allowDestructiveFromEnv reports whether the operator opted in to destructive
// methods. Exact-"1" like the write gate (fail closed on anything else); only
// meaningful together with allowWriteFromEnv (the two-key gate).
func allowDestructiveFromEnv() bool {
	return os.Getenv(allowDestructiveEnv) == "1"
}

// slackAPIInputSchema is the tool's input schema, supplied explicitly instead
// of being reflected from slackAPIInput. The reflected schema sets
// additionalProperties:false, which makes a strict MCP harness REJECT a call
// whose arguments it flattened to the top level (the observed Hermes failure,
// "unexpected additional properties"). This schema allows additional properties
// at the top level and inside params, so flattened or nested arguments both pass
// validation; slackAPIInput.UnmarshalJSON then normalizes whatever shape arrives.
func slackAPIInputSchema() *jsonschema.Schema {
	// Each &jsonschema.Schema{} must be a DISTINCT instance: the resolver
	// requires the schema graph to form a tree (no shared nodes).
	return &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"workspace": {
				Type:        "string",
				Description: "Slack workspace URL to act as, e.g. https://acme.slack.com. Selects which account's token to use. Omit when only one workspace is signed in.",
			},
			"method": {
				Type:        "string",
				Description: "Slack Web API method, e.g. conversations.history or chat.postMessage. Must be on the server's allowlist (see the tool description).",
			},
			// No Type constraint: the SDK validator runs on the wire BEFORE
			// UnmarshalJSON, so constraining params to "object" would reject the
			// JSON-string and null shapes this tool also accepts. An open schema
			// lets any of object/string/null through; UnmarshalJSON normalizes it.
			"params": {
				Description: "Method arguments, normally a JSON object, e.g. {\"query\":\"from:me\"}. May also be a JSON string containing that object, or omitted when the arguments are placed directly at the top level next to method.",
			},
		},
		Required:             []string{"method"},
		AdditionalProperties: &jsonschema.Schema{},
	}
}

// sortedMethods returns m's keys sorted, for a stable tool description.
func sortedMethods(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// toolDescription builds slack_api_call's description, enumerating the EXACT
// allowlist and the live gate state so a calling agent chooses a valid method
// and knows up front which calls will be rejected.
func toolDescription(cfg mcpConfig) string {
	state := func(on bool) string {
		if on {
			return "ENABLED"
		}
		return "disabled"
	}
	var b strings.Builder
	b.WriteString("Calls a Slack Web API method on your behalf, injecting your Slack credentials ")
	b.WriteString("server-side so they NEVER enter the AI's context. Provide `method`, `params` (its ")
	b.WriteString("arguments), and optionally `workspace` (the Slack URL to act as; omit when only one ")
	b.WriteString("account is signed in). ONLY these allowlisted methods work — any other method is rejected:\n")
	b.WriteString("• READ (always available): " + strings.Join(sortedMethods(readMethods), ", ") + "\n")
	b.WriteString("• WRITE [" + state(cfg.allowWrite) + "]: " + strings.Join(sortedMethods(writeMethods), ", ") + "\n")
	b.WriteString("• DESTRUCTIVE [" + state(cfg.allowWrite && cfg.allowDestructive) + "]: " + strings.Join(sortedMethods(destructiveMethods), ", ") + "\n")
	b.WriteString("How to use: start with auth.test to confirm the active account; find a channel ID via ")
	b.WriteString("conversations.list, then e.g. chat.postMessage with params {\"channel\":\"C0123\",\"text\":\"hi\"}. ")
	b.WriteString("Nested values (blocks, attachments) are JSON-encoded automatically. ")
	b.WriteString("Passing arguments: put them in `params` as a JSON object; if your harness cannot send a ")
	b.WriteString("nested object, you may instead place the arguments at the top level next to `method`, or ")
	b.WriteString("pass `params` as a JSON string — all three are accepted. ")
	b.WriteString("IMPORTANT: this tool is ONLINE (contacts slack.com) and the Slack response is returned ")
	b.WriteString("to the AI — the credential is protected, but response data is not and may contain private ")
	b.WriteString("workspace information.")
	return b.String()
}

// slackAPIInput is the tool's input.
type slackAPIInput struct {
	Workspace string         `json:"workspace,omitempty" jsonschema:"Slack workspace URL to act as, e.g. https://acme.slack.com — selects which xoxc token to use. Omit when only one workspace is signed in."`
	Method    string         `json:"method"    jsonschema:"Slack Web API method, e.g. conversations.history or chat.postMessage. Must be on the server's allowlist."`
	Params    map[string]any `json:"params,omitempty" jsonschema:"Method arguments as a JSON object, e.g. {\"channel\":\"C123\",\"text\":\"hi\"} or {\"query\":\"from:me\"}. Accepted three ways for harness compatibility: (1) a JSON object here; (2) a JSON string here; (3) the arguments placed directly at the top level alongside method. Nested values (blocks, attachments) are JSON-encoded automatically."`
}

// reservedInputKeys are the top-level fields that are NOT Slack method
// arguments, so they are never folded into Params.
var reservedInputKeys = map[string]bool{"workspace": true, "method": true, "params": true}

// UnmarshalJSON makes the tool robust to how different MCP harnesses serialize
// a nested argument object. Some harnesses drop the contents of a nested object
// property (arriving as "params": {}), stringify it, or flatten the arguments to
// the top level. This recovers the Slack method arguments in all those shapes:
//  1. params as a JSON object (the normal case),
//  2. params as a JSON string containing an object,
//  3. method arguments placed at the top level next to "method".
//
// A top-level key never overrides a key already present inside params.
func (in *slackAPIInput) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if v, ok := raw["workspace"]; ok {
		if err := json.Unmarshal(v, &in.Workspace); err != nil {
			return fmt.Errorf("workspace: %w", err)
		}
	}
	if v, ok := raw["method"]; ok {
		if err := json.Unmarshal(v, &in.Method); err != nil {
			return fmt.Errorf("method: %w", err)
		}
	}
	in.Params = map[string]any{}
	if v, ok := raw["params"]; ok {
		obj, err := decodeParams(v)
		if err != nil {
			return fmt.Errorf("params: %w", err)
		}
		for k, val := range obj {
			in.Params[k] = val
		}
	}
	// Fold any remaining top-level keys (flattened arguments) into params,
	// without overriding an explicit params entry.
	for k, v := range raw {
		if reservedInputKeys[k] {
			continue
		}
		if _, exists := in.Params[k]; exists {
			continue
		}
		var val any
		if err := json.Unmarshal(v, &val); err != nil {
			return fmt.Errorf("argument %q: %w", k, err)
		}
		in.Params[k] = val
	}
	return nil
}

// decodeParams accepts a JSON object, a JSON string containing an object, or an
// empty/null value, and returns the resulting map (empty when there is nothing).
func decodeParams(v json.RawMessage) (map[string]any, error) {
	trimmed := strings.TrimSpace(string(v))
	if trimmed == "" || trimmed == "null" {
		return map[string]any{}, nil
	}
	var obj map[string]any
	if err := json.Unmarshal(v, &obj); err == nil {
		return obj, nil
	}
	// Maybe it is a JSON string wrapping a JSON object.
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return nil, fmt.Errorf("not a JSON object or string: %s", trimmed)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return map[string]any{}, nil
	}
	var obj2 map[string]any
	if err := json.Unmarshal([]byte(s), &obj2); err != nil {
		return nil, fmt.Errorf("string value is not a JSON object: %q", s)
	}
	return obj2, nil
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
//
// Redirects are NEVER followed: Go's default client re-sends the Authorization
// and Cookie headers on a same-host (or subdomain) redirect, so a malicious or
// compromised endpoint answering 30x with a Location of, say,
// https://evil.slack.com/collect or http://127.0.0.1/ would receive the live
// credential (a header-leak + SSRF). ErrUseLastResponse makes Do return the 30x
// response itself without following it, so the credential is never resent.
func (h *handlers) client() *http.Client {
	if h.httpClient != nil {
		return h.httpClient
	}
	return &http.Client{
		Timeout: slackRequestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// baseURL returns the Slack Web API base for the given workspace URL. Tests
// point this at an httptest server via baseURLStr. In production it is derived
// from the workspace host so GovSlack (*.slack-gov.com) workspaces hit the
// GovSlack API host instead of the commercial one; everything else uses
// slack.com.
func (h *handlers) baseURL(workspaceURL string) string {
	if h.baseURLStr != "" {
		return h.baseURLStr
	}
	if host := hostOf(workspaceURL); strings.HasSuffix(host, ".slack-gov.com") || host == "slack-gov.com" {
		return "https://slack-gov.com/api/"
	}
	return slackAPIBaseURL
}

// hostOf returns the lowercased host of a workspace URL, or "" if unparseable.
func hostOf(workspaceURL string) string {
	u, err := url.Parse(workspaceURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// validateMethod enforces the shape + allowlist, fail-closed.
func validateMethod(method string, allowWrite, allowDestructive bool) error {
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
	if destructiveMethods[method] {
		if !allowWrite || !allowDestructive {
			return fmt.Errorf("method %q is a destructive method; it is disabled — set BOTH %s=1 and %s=1 to enable it", method, allowWriteEnv, allowDestructiveEnv)
		}
		return nil
	}
	return fmt.Errorf("method %q is not on the allowlist (reads are always available; writes require %s=1; destructive methods require %s=1 too)", method, allowWriteEnv, allowDestructiveEnv)
}

// encodeParams flattens params into a urlencoded form body. Scalars become
// their string form; any array/object value is JSON-encoded, as Slack's
// form-encoded endpoints expect for fields like blocks and attachments.
// stripAuthParams returns a copy of params with any auth-bearing key removed, so
// a caller cannot supply a Slack "token" form field to override or shadow the
// server-injected credential. Matching is case-insensitive.
func stripAuthParams(params map[string]any) map[string]any {
	out := make(map[string]any, len(params))
	for k, v := range params {
		if strings.EqualFold(strings.TrimSpace(k), "token") {
			continue
		}
		out[k] = v
	}
	return out
}

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
		// Skip short values: real credentials (xoxc tokens, the d cookie) are long,
		// whereas a short value (e.g. a numeric d-s) would blanket-match ordinary
		// response text — a message `ts` second, a count — and corrupt it. A short
		// value is also not usefully secret on its own.
		if len(s) < minVariantLen {
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

// cookieHeader builds the Cookie header value for the given workspace. The d
// cookie is required; d-s is appended only when present. Slack's d cookie is
// domain-wide and shared across every workspace on the SAME host family, but a
// user signed into both commercial Slack (.slack.com) and GovSlack
// (.slack-gov.com) has two distinct d cookies on different domains — so cookies
// are first filtered to those whose host matches the target workspace. If, after
// that filter, two DIFFERENT d (or d-s) values remain (e.g. a stale session from
// a previous login on the same domain), the pairing is ambiguous — rather than
// pick one arbitrarily, fail closed so a call can't run under the wrong session.
func cookieHeader(cookies []slacktokens.Cookie, workspaceURL string) (string, error) {
	wantHost := hostOf(workspaceURL)
	var d, ds string
	haveD, haveDS := false, false
	for _, c := range cookies {
		// Skip cookies that carry a host and don't apply to this workspace. A
		// cookie with no recorded host is treated as applicable (back-compat).
		if c.Host != "" && wantHost != "" && !cookieHostMatches(wantHost, c.Host) {
			continue
		}
		switch c.Name {
		case "d":
			if haveD && c.Value != d {
				return "", errors.New("multiple distinct 'd' cookies found for this workspace — ambiguous Slack session; sign out of stale workspaces and retry")
			}
			d, haveD = c.Value, true
		case "d-s":
			if haveDS && c.Value != ds {
				return "", errors.New("multiple distinct 'd-s' cookies found for this workspace — ambiguous Slack session; sign out of stale workspaces and retry")
			}
			ds, haveDS = c.Value, true
		}
	}
	if d == "" {
		return "", errors.New("no d cookie available for this workspace — cannot authenticate to Slack")
	}
	h := "d=" + d
	if ds != "" {
		h += "; d-s=" + ds
	}
	return h, nil
}

// cookieHostMatches reports whether a cookie stored under hostKey (a Chromium
// host_key such as ".slack.com", "slack.com", or "acme.slack.com") applies to
// the workspace host wantHost. A leading-dot host_key is a domain cookie that
// matches the domain and all its subdomains; a bare host_key matches exactly.
func cookieHostMatches(wantHost, hostKey string) bool {
	hostKey = strings.ToLower(hostKey)
	if strings.HasPrefix(hostKey, ".") {
		domain := strings.TrimPrefix(hostKey, ".")
		return wantHost == domain || strings.HasSuffix(wantHost, "."+domain)
	}
	return wantHost == hostKey
}

func sortedKeys(m map[string]slacktokens.Workspace) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// call performs one authenticated Slack Web API request and shapes the result.
// It resolves credentials in-process, injects them server-side, and redacts any
// credential from the response, which never leaves this function.
//
// IMPORTANT: call performs NO method authorization — enforcing the allowlist or
// a destructive gate is the CALLER's responsibility, so every caller MUST decide
// `method` is permitted before invoking it. It returns a non-nil *CallToolResult
// only on an infrastructure failure (reported as IsError); a reached-Slack call,
// including a Slack-level ok:false or an HTTP 429, returns (nil, out).
func (h *handlers) call(ctx context.Context, workspace, method string, params map[string]any) (*mcp.CallToolResult, slackAPIOutput) {
	// Resolve live credentials in-process.
	r, err := h.credsResult()
	if err != nil {
		return errorResult(err), slackAPIOutput{}
	}
	wsURL, ws, err := resolveWorkspace(r.Tokens, workspace)
	if err != nil {
		return errorResult(err), slackAPIOutput{}
	}
	if ws.Token == "" {
		return errorResult(fmt.Errorf("workspace %q has no token", wsURL)), slackAPIOutput{}
	}
	cookie, err := cookieHeader(r.Cookies, wsURL)
	if err != nil {
		return errorResult(err), slackAPIOutput{}
	}

	// Strip any caller-supplied auth parameter: the credential is injected
	// server-side via the Authorization header and must be authoritative. A
	// "token" form field would otherwise let a caller shadow or confuse the
	// server credential. (Case-insensitive; Slack treats the key as "token".)
	params = stripAuthParams(params)

	form, err := encodeParams(params)
	if err != nil {
		return errorResult(err), slackAPIOutput{}
	}

	// Build and send. The URL is constrained: baseURL is a constant and the
	// caller validated `method` (allowlist or typed tool), so it cannot escape
	// the /api/ path.
	secrets := collectSecrets(r)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL(wsURL)+method, strings.NewReader(form.Encode())) // #nosec G107 -- method is validated by the caller (allowlist or typed tool); base is derived from a hardcoded host set.
	if err != nil {
		return errorResult(fmt.Errorf("build request: %w", err)), slackAPIOutput{}
	}
	req.Header.Set("Authorization", "Bearer "+ws.Token)
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "slacktokens-mcp/"+version)

	resp, err := h.client().Do(req)
	if err != nil {
		// Do not wrap req/err with headers — avoid any chance of logging creds.
		return errorResult(fmt.Errorf("slack request failed: %w", err)), slackAPIOutput{}
	}
	defer func() { _ = resp.Body.Close() }()

	// Read the body, bounded at the cap plus one byte to detect overflow.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return errorResult(fmt.Errorf("read slack response: %w", err)), slackAPIOutput{}
	}

	out := slackAPIOutput{
		Status:    resp.StatusCode,
		Workspace: wsURL,
		Method:    method,
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		// Redact defensively: a response header is scrubbed exactly like the body
		// so a reflected credential can never ride out via Retry-After.
		out.RetryAfter = redactSecrets(resp.Header.Get("Retry-After"), secrets)
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
		return nil, out
	}

	// Complete response: redact credentials (and their encoding variants) in
	// full before the body enters the model context, then parse Slack's ok flag.
	out.Body = redactSecrets(string(data), secrets)
	var probe struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(data, &probe) == nil {
		out.OK = probe.OK
	}
	return nil, out
}

// slackAPICall is the generic proxy tool handler. It enforces the fail-closed
// method allowlist, then delegates the transport to call. Destructive methods
// (chat.delete/chat.update) run only when both the write and destructive gates
// are set; otherwise they are rejected before any network call.
func (h *handlers) slackAPICall(ctx context.Context, _ *mcp.CallToolRequest, in slackAPIInput) (*mcp.CallToolResult, slackAPIOutput, error) {
	if err := validateMethod(in.Method, h.cfg.allowWrite, h.cfg.allowDestructive); err != nil {
		return errorResult(err), slackAPIOutput{}, nil
	}
	res, out := h.call(ctx, in.Workspace, in.Method, in.Params)
	return res, out, nil
}

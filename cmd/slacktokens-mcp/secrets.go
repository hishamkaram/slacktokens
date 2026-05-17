// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

package main

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/hishamkaram/slacktokens"
)

// allowRawEnv is the environment variable that, when truthy, makes the read
// tools inline raw credential values instead of masked previews. Unset (the
// default) keeps every read tool masked so Slack secrets never enter the
// calling model's context.
const allowRawEnv = "SLACKTOKENS_MCP_ALLOW_RAW"

// allowRawFromEnv reports whether the operator opted in to raw credential
// output by setting SLACKTOKENS_MCP_ALLOW_RAW to a truthy value.
func allowRawFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(allowRawEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// maskSecret returns a short, non-reversible preview of a secret: enough for a
// human to recognise their own credential, useless as a credential itself.
// Empty input yields empty output; anything short enough that a head/tail
// preview would reveal most of it collapses to a bare ellipsis.
func maskSecret(s string) string {
	switch {
	case s == "":
		return ""
	case len(s) <= 12:
		return "…"
	default:
		return s[:6] + "…" + s[len(s)-4:]
	}
}

// toMaskedWorkspaces converts library workspaces to the MCP output shape. The
// raw token is included only when allowRaw is set.
func toMaskedWorkspaces(in map[string]slacktokens.Workspace, allowRaw bool) map[string]maskedWorkspace {
	out := make(map[string]maskedWorkspace, len(in))
	for url, w := range in {
		mw := maskedWorkspace{
			Name:         w.Name,
			TokenPreview: maskSecret(w.Token),
			TokenPresent: w.Token != "",
		}
		if allowRaw {
			mw.Token = w.Token
		}
		out[url] = mw
	}
	return out
}

// toMaskedCookie converts one library cookie to the MCP output shape. The raw
// value is included only when allowRaw is set.
func toMaskedCookie(c slacktokens.Cookie, allowRaw bool) maskedCookie {
	mc := maskedCookie{
		Name:         c.Name,
		ValuePreview: maskSecret(c.Value),
		Present:      c.Value != "",
	}
	if allowRaw {
		mc.Value = c.Value
	}
	return mc
}

// toMaskedCookies converts a slice of library cookies to the MCP output shape.
func toMaskedCookies(in []slacktokens.Cookie, allowRaw bool) []maskedCookie {
	out := make([]maskedCookie, len(in))
	for i, c := range in {
		out[i] = toMaskedCookie(c, allowRaw)
	}
	return out
}

// writeCredentialsFile writes the live credentials in r as indented JSON to a
// freshly created file inside dir. os.CreateTemp creates the file with mode
// 0600, so it is readable only by the current OS user. It returns the file
// path and the number of bytes written — never the credential bytes
// themselves, so the secrets do not flow back to the MCP caller.
func writeCredentialsFile(dir string, r slacktokens.Result) (path string, n int, err error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", 0, err
	}
	data = append(data, '\n')

	f, err := os.CreateTemp(dir, "slack-creds-*.json")
	if err != nil {
		return "", 0, err
	}
	n, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(f.Name())
		return "", 0, werr
	}
	if cerr != nil {
		_ = os.Remove(f.Name())
		return "", 0, cerr
	}
	return f.Name(), n, nil
}

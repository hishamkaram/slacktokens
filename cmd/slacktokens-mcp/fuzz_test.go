// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package main

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/hishamkaram/slacktokens"
)

// FuzzSlackAPIInputNeverForwardsToken checks the credential-shadowing guard:
// whatever argument shape a harness sends (nested, stringified, or flattened),
// the form sent to Slack never carries a caller-supplied token field.
func FuzzSlackAPIInputNeverForwardsToken(f *testing.F) {
	for _, seed := range []string{
		`{"method":"auth.test"}`,
		`{"method":"search.messages","params":{"query":"from:me","token":"xoxc-evil"}}`,
		`{"method":"search.messages","params":"{\"Token\":\"x\",\"query\":\"q\"}"}`,
		`{"method":"chat.postMessage","channel":"C1"," token ":"x","TOKEN":"y"}`,
		`{"method":"x","params":null,"workspace":"https://acme.slack.com"}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var in slackAPIInput
		if err := json.Unmarshal(data, &in); err != nil {
			return
		}
		form, err := encodeParams(stripAuthParams(in.Params))
		if err != nil {
			return
		}
		for key := range form {
			if strings.EqualFold(strings.TrimSpace(key), "token") {
				t.Fatalf("caller-supplied %q reached the Slack form for input %q", key, data)
			}
		}
	})
}

// FuzzRedactSecretsRemovesCredential checks that a response body never keeps a
// live credential, in raw, URL-encoded, or JSON-escaped form, after redaction.
// Real credentials never contain brackets, so the generated secret excludes
// them; a secret built from "[REDACTED]" fragments could otherwise re-form
// across the placeholder.
func FuzzRedactSecretsRemovesCredential(f *testing.F) {
	f.Add("xoxc-1234567890-abcdef", `{"ok":true,"token":"xoxc-1234567890-abcdef"}`)
	f.Add("xoxd-a%2Fb%2Bc%3D%3Dlong", `{"cookie":"xoxd-a/b+c==long","esc":"xoxd-a\/b+c==long"}`)
	f.Add("abcdefgh", "abcdefghabcdefgh-abcdefg")
	f.Fuzz(func(t *testing.T, secret, body string) {
		if len(secret) < 8 || strings.ContainsAny(secret, "[]") {
			return
		}
		secrets := collectSecrets(slacktokens.Result{
			Tokens:  map[string]slacktokens.Workspace{"https://acme.slack.com": {Token: secret}},
			Cookies: []slacktokens.Cookie{{Name: "d", Value: secret}},
		})
		for _, variant := range secrets {
			if strings.ContainsAny(variant, "[]") {
				return
			}
		}
		out := redactSecrets(body+secret+body, secrets)
		for _, variant := range secrets {
			if strings.Contains(out, variant) {
				t.Fatalf("credential form %q survived redaction: %q", variant, out)
			}
		}
	})
}

// FuzzValidateSlackUploadURLDialsSlackHost checks for parser differentials: a
// URL the validator accepts must make net/http dial the Slack upload host over
// HTTPS on the default port, so the file bytes cannot be steered elsewhere.
func FuzzValidateSlackUploadURLDialsSlackHost(f *testing.F) {
	for _, seed := range []string{
		"https://files.slack.com/upload/v1/ticket",
		"https://files.slack-gov.com/upload/v1/ticket",
		"https://FILES.SLACK.COM/upload/v1/x?y=1",
		"https://files.slack.com@evil.example/upload/v1/x",
		"https://evil.example\\@files.slack.com/upload/v1/x",
		"https://files.slack.com:443/upload/v1/x",
		"https://files.slack.com./upload/v1/x",
		"https://files.slack.com%2eevil.example/upload/v1/x",
	} {
		f.Add(seed, "https://acme.slack.com")
		f.Add(seed, "https://acme.slack-gov.com")
	}
	f.Fuzz(func(t *testing.T, raw, workspace string) {
		if validateSlackUploadURL(raw, workspace) != nil {
			return
		}
		req, err := http.NewRequest(http.MethodPost, raw, nil)
		if err != nil {
			t.Fatalf("validator accepted %q but net/http rejects it: %v", raw, err)
		}
		host := strings.ToLower(req.URL.Host)
		if req.URL.Scheme != "https" || (host != "files.slack.com" && host != "files.slack-gov.com") {
			t.Fatalf("validator accepted %q, which dials %s://%s", raw, req.URL.Scheme, req.URL.Host)
		}
	})
}

// FuzzValidateSlackFileURLDialsSlackHost checks for parser differentials: a URL
// the validator accepts must make net/http dial a Slack file host over HTTPS on
// the default port, so the session cannot be sent elsewhere.
func FuzzValidateSlackFileURLDialsSlackHost(f *testing.F) {
	for _, seed := range []string{
		"https://files.slack.com/files-pri/T1-F1/download/a.pdf",
		"https://files-origin.slack.com/files-pri/T1-F1/download/a.pdf",
		"https://files.slack-gov.com/files-pri/T1-F1/a.pdf",
		"https://FILES.SLACK.COM/files-pri/T1-F1/a.pdf?x=1",
		"https://files.slack.com@evil.example/a.pdf",
		"https://evil.example\\@files.slack.com/a.pdf",
		"https://files.slack.com:443/a.pdf",
		"https://files.slack.com./a.pdf",
		"https://files.slack.com%2eevil.example/a.pdf",
		"//files.slack.com/a.pdf",
	} {
		f.Add(seed, "https://acme.slack.com")
		f.Add(seed, "https://acme.slack-gov.com")
	}
	f.Fuzz(func(t *testing.T, raw, workspace string) {
		if validateSlackFileURL(raw, workspace) != nil {
			return
		}
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		if err != nil {
			t.Fatalf("validator accepted %q but net/http rejects it: %v", raw, err)
		}
		host := strings.ToLower(req.URL.Host)
		if req.URL.Scheme != "https" || (host != "files.slack.com" && host != "files-origin.slack.com" && host != "files.slack-gov.com") {
			t.Fatalf("validator accepted %q, which dials %s://%s", raw, req.URL.Scheme, req.URL.Host)
		}
	})
}

// FuzzDownloadFileNameIsOneSafeComponent checks that any Slack file name maps
// to a single local path component inside the download root.
func FuzzDownloadFileNameIsOneSafeComponent(f *testing.F) {
	for _, seed := range []string{"report.pdf", "../../etc/passwd", `..\..\win.ini`, "", "...", "a/b", "C:x", "\x00", "報告書.pdf", "\xff\xfe"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got := downloadFileName("F123", name)
		if got != "F123" && !strings.HasPrefix(got, "F123-") {
			t.Fatalf("downloadFileName(%q) = %q lost its file ID prefix", name, got)
		}
		if !fs.ValidPath(got) || strings.ContainsAny(got, `/\:`) || filepath.Base(got) != got || filepath.IsAbs(got) || filepath.VolumeName(got) != "" {
			t.Fatalf("downloadFileName(%q) = %q is not one relative path component", name, got)
		}
		if len(got) > maxDownloadNameBytes || !utf8.ValidString(got) || strings.HasSuffix(got, ".") || strings.HasSuffix(got, " ") {
			t.Fatalf("downloadFileName(%q) = %q is not portable", name, got)
		}
	})
}

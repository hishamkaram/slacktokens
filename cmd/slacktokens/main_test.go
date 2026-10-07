// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hishamkaram/slacktokens"
)

func sampleResult() slacktokens.Result {
	return slacktokens.Result{
		Tokens: map[string]slacktokens.Workspace{
			"https://acme.slack.com": {Token: "xoxc-secret", Name: "Acme"},
		},
		Cookie:  slacktokens.Cookie{Name: "d", Value: "xoxd-secret"},
		Cookies: []slacktokens.Cookie{{Name: "d", Value: "xoxd-secret"}},
	}
}

func TestWriteResultFile_Mode0600AndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	if err := writeResultFile(path, sampleResult()); err != nil {
		t.Fatalf("writeResultFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("mode = %#o, want 0600", perm)
		}
	}

	data, err := os.ReadFile(path) // #nosec G304 -- test TempDir path.
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var got slacktokens.Result
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("not valid JSON Result: %v", err)
	}
	if got.Tokens["https://acme.slack.com"].Token != "xoxc-secret" {
		t.Errorf("token round-trip mismatch: %+v", got.Tokens)
	}
	if got.Cookie.Value != "xoxd-secret" {
		t.Errorf("cookie round-trip mismatch: %+v", got.Cookie)
	}
}

func TestWriteResultFile_RefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeResultFile(path, sampleResult()); err == nil {
		t.Fatal("expected refusal to overwrite an existing file")
	}
	// The original content must be untouched.
	b, _ := os.ReadFile(path) // #nosec G304 -- test TempDir path.
	if string(b) != "existing" {
		t.Errorf("existing file was modified: %q", b)
	}
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hishamkaram/slacktokens"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func response(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func TestSlackFileUploadUsesAtomicSlackFlow(t *testing.T) {
	root := t.TempDir()
	contents := []byte("synthetic ad creative")
	if err := os.WriteFile(filepath.Join(root, "creative.mp4"), contents, 0600); err != nil {
		t.Fatal(err)
	}
	var uploaded []byte
	var calls []string
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.test" {
			if req.Header.Get("Authorization") != "Bearer "+testXOXC || req.Header.Get("Cookie") != "d="+testXOXD+"; d-s=123" {
				t.Errorf("API request did not carry broker credentials")
			}
			switch req.URL.Path {
			case "/api/files.getUploadURLExternal":
				calls = append(calls, "get-url")
				if err := req.ParseForm(); err != nil {
					t.Errorf("parse get-url form: %v", err)
				}
				if req.PostForm.Get("filename") != "creative.mp4" || req.PostForm.Get("length") != "21" {
					t.Errorf("get-url args = %v", req.PostForm)
				}
				return response(req, 200, `{"ok":true,"upload_url":"https://files.slack.com/upload/v1/opaque-ticket","file_id":"F123"}`), nil
			case "/api/files.completeUploadExternal":
				calls = append(calls, "complete")
				if err := req.ParseForm(); err != nil {
					t.Errorf("parse completion form: %v", err)
				}
				if req.PostForm.Get("channel_id") != "C123" || req.PostForm.Get("thread_ts") != "1700000000.123456" || req.PostForm.Get("initial_comment") != "Review this" {
					t.Errorf("completion args = %v", req.PostForm)
				}
				var files []map[string]string
				if err := json.Unmarshal([]byte(req.PostForm.Get("files")), &files); err != nil || len(files) != 1 || files[0]["id"] != "F123" || files[0]["title"] != "Campaign review" {
					t.Errorf("completion files = %q, err=%v", req.PostForm.Get("files"), err)
				}
				return response(req, 200, `{"ok":true,"files":[{"id":"F123"}]}`), nil
			default:
				t.Errorf("unexpected Slack API request %s", req.URL.Path)
				return response(req, 404, `{}`), nil
			}
		}
		if req.URL.Host != "files.slack.com" {
			t.Errorf("unexpected transfer host %q", req.URL.Host)
		}
		calls = append(calls, "upload")
		if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
			t.Errorf("broker credentials leaked to upload host")
		}
		if req.ContentLength != int64(len(contents)) {
			t.Errorf("ContentLength = %d", req.ContentLength)
		}
		var err error
		uploaded, err = io.ReadAll(req.Body)
		if err != nil {
			t.Errorf("read uploaded bytes: %v", err)
		}
		return response(req, 200, "ok"), nil
	})}
	h := &handlers{
		cfg:        mcpConfig{allowWrite: true, uploadRoot: root},
		credsFn:    func() (slacktokens.Result, error) { return testResult(), nil },
		httpClient: client,
		baseURLStr: "https://api.test/api/",
	}
	res, out, err := h.slackFileUpload(context.Background(), nil, slackFileUploadInput{
		RelativePath:   "creative.mp4",
		ChannelID:      "C123",
		ThreadTS:       "1700000000.123456",
		Title:          "Campaign review",
		InitialComment: "Review this",
	})
	if err != nil || res != nil {
		t.Fatalf("slackFileUpload returned result=%v err=%v", res, err)
	}
	if !out.OK || out.FileID != "F123" || out.Workspace != "https://acme.slack.com" {
		t.Fatalf("output = %+v", out)
	}
	if string(uploaded) != string(contents) {
		t.Fatalf("uploaded bytes = %q", uploaded)
	}
	if strings.Join(calls, ",") != "get-url,upload,complete" {
		t.Fatalf("call order = %v", calls)
	}
	serialized, _ := json.Marshal(out)
	if strings.Contains(string(serialized), "opaque-ticket") || strings.Contains(string(serialized), "upload/v1") {
		t.Fatalf("temporary upload URL reached tool output: %s", serialized)
	}
}

func TestSlackFileUploadRejectsWritesAndUnsafePathsBeforeSlack(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	h := &handlers{
		cfg:        mcpConfig{uploadRoot: root},
		credsFn:    func() (slacktokens.Result, error) { calls++; return testResult(), nil },
		baseURLStr: "https://api.test/api/",
	}
	res, _, err := h.slackFileUpload(context.Background(), nil, slackFileUploadInput{RelativePath: "ok.txt", ChannelID: "C123"})
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("disabled upload result=%v err=%v", res, err)
	}
	if calls != 0 {
		t.Fatalf("disabled upload made %d Slack credential lookups", calls)
	}

	h.cfg.allowWrite = true
	for _, path := range []string{"../outside.txt", "/tmp/outside.txt", "", "a\\..\\outside.txt"} {
		res, _, err := h.slackFileUpload(context.Background(), nil, slackFileUploadInput{RelativePath: path, ChannelID: "C123"})
		if err != nil || res == nil || !res.IsError {
			t.Errorf("path %q result=%v err=%v, want tool error", path, res, err)
		}
	}
	if calls != 0 {
		t.Fatalf("unsafe paths made %d Slack credential lookups", calls)
	}
}

func TestOpenUploadFileRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	h := &handlers{cfg: mcpConfig{uploadRoot: root}}
	if f, _, _, closeFile, err := h.openUploadFile("link.txt"); err == nil {
		closeFile()
		f.Close()
		t.Fatal("opened a symlink that escapes the configured upload root")
	}
}

func TestSlackFileUploadRejectsUntrustedURLWithoutReturningIt(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	var completeCalled bool
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/files.getUploadURLExternal" {
			return response(req, 200, `{"ok":true,"upload_url":"https://evil.example/upload/v1/secret-ticket","file_id":"F123"}`), nil
		}
		completeCalled = true
		return response(req, 200, `{"ok":true}`), nil
	})}
	h := &handlers{
		cfg:        mcpConfig{allowWrite: true, uploadRoot: root},
		credsFn:    func() (slacktokens.Result, error) { return testResult(), nil },
		httpClient: client,
		baseURLStr: "https://api.test/api/",
	}
	res, _, err := h.slackFileUpload(context.Background(), nil, slackFileUploadInput{RelativePath: "ok.txt", ChannelID: "C123"})
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("result=%v err=%v, want tool error", res, err)
	}
	if completeCalled {
		t.Fatal("completed an upload after rejecting its URL")
	}
	serialized, _ := json.Marshal(res)
	if strings.Contains(string(serialized), "secret-ticket") || strings.Contains(string(serialized), "evil.example") {
		t.Fatalf("untrusted upload URL reached tool result: %s", serialized)
	}
}

func TestValidateSlackUploadURL(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		workspace string
		wantErr   bool
	}{
		{"commercial", "https://files.slack.com/upload/v1/ticket", "https://acme.slack.com", false},
		{"gov", "https://files.slack-gov.com/upload/v1/ticket", "https://acme.slack-gov.com", false},
		{"wrong host", "https://evil.example/upload/v1/ticket", "https://acme.slack.com", true},
		{"wrong scheme", "http://files.slack.com/upload/v1/ticket", "https://acme.slack.com", true},
		{"wrong path", "https://files.slack.com/other/ticket", "https://acme.slack.com", true},
		{"userinfo", "https://user@files.slack.com/upload/v1/ticket", "https://acme.slack.com", true},
		{"explicit port", "https://files.slack.com:8443/upload/v1/ticket", "https://acme.slack.com", true},
		{"cross family", "https://files.slack.com/upload/v1/ticket", "https://acme.slack-gov.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSlackUploadURL(tc.raw, tc.workspace)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateSlackUploadURL() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestSlackFileUploadDoesNotFollowUploadRedirect(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ok.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	var transferCalls int
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/files.getUploadURLExternal" {
			return response(req, 200, `{"ok":true,"upload_url":"https://files.slack.com/upload/v1/ticket","file_id":"F123"}`), nil
		}
		transferCalls++
		resp := response(req, http.StatusTemporaryRedirect, "")
		resp.Header.Set("Location", "https://evil.example/collect")
		return resp, nil
	})}
	h := &handlers{
		cfg:        mcpConfig{allowWrite: true, uploadRoot: root},
		credsFn:    func() (slacktokens.Result, error) { return testResult(), nil },
		httpClient: client,
		baseURLStr: "https://api.test/api/",
	}
	res, _, err := h.slackFileUpload(context.Background(), nil, slackFileUploadInput{RelativePath: "ok.txt", ChannelID: "C123"})
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("result=%v err=%v, want transfer error", res, err)
	}
	if transferCalls != 1 {
		t.Fatalf("transfer calls = %d, want 1", transferCalls)
	}
}

func TestSlackMethodFailureOnlyReturnsSafeErrorCodes(t *testing.T) {
	if got := slackMethodFailure("share uploaded file", `{"ok":false,"error":"missing_scope"}`).Error(); got != "Slack could not share uploaded file: missing_scope" {
		t.Fatalf("safe API error = %q", got)
	}
	if got := slackMethodFailure("share uploaded file", `{"ok":false,"error":"private detail"}`).Error(); strings.Contains(got, "private detail") {
		t.Fatalf("unsafe API error leaked into result: %q", got)
	}
}

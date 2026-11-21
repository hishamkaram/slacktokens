// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/hishamkaram/slacktokens"
)

const testFileURL = "https://files.slack.com/files-pri/T1-F123/download/report.pdf"

// fileInfoBody is a files.info response for F123 served from fileURL.
func fileInfoBody(fileURL string) string {
	return `{"ok":true,"file":{"id":"F123","name":"report.pdf","mimetype":"application/pdf","size":8,"is_external":false,"url_private":"https://files.slack.com/files-pri/T1-F123/report.pdf","url_private_download":"` + fileURL + `"}}`
}

// downloadHandler returns handlers whose Slack API and file host are served by
// transport, with downloads saved to root.
func downloadHandler(root string, transport roundTripFunc) *handlers {
	return &handlers{
		cfg:        mcpConfig{downloadRoot: root},
		credsFn:    func() (slacktokens.Result, error) { return testResult(), nil },
		httpClient: &http.Client{Transport: transport},
		baseURLStr: "https://api.test/api/",
	}
}

// assertNoSecrets fails when a tool result or output carries a test credential.
func assertNoSecrets(t *testing.T, v any) {
	t.Helper()
	serialized, _ := json.Marshal(v)
	if strings.Contains(string(serialized), testXOXC) || strings.Contains(string(serialized), testXOXD) {
		t.Fatalf("credential reached tool output: %s", serialized)
	}
}

// rootEntries lists the names in root, so a test can check nothing else, such
// as a temporary .part file, was left behind.
func rootEntries(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestSlackFileDownloadSavesFileWithSession(t *testing.T) {
	root := t.TempDir()
	var calls []string
	h := downloadHandler(root, func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "Bearer "+testXOXC || req.Header.Get("Cookie") != "d="+testXOXD+"; d-s=123" {
			t.Errorf("%s request did not carry the session", req.URL.Host)
		}
		if req.URL.Host == "api.test" {
			calls = append(calls, "info")
			if err := req.ParseForm(); err != nil {
				t.Errorf("parse files.info form: %v", err)
			}
			if req.URL.Path != "/api/files.info" || req.PostForm.Get("file") != "F123" {
				t.Errorf("files.info request = %s %v", req.URL.Path, req.PostForm)
			}
			return response(req, 200, fileInfoBody(testFileURL)), nil
		}
		calls = append(calls, "download")
		if req.Method != http.MethodGet || req.URL.String() != testFileURL {
			t.Errorf("download request = %s %s", req.Method, req.URL)
		}
		resp := response(req, 200, "%PDF-1.7")
		resp.Header.Set("Content-Type", "application/pdf")
		return resp, nil
	})
	res, out, err := h.slackFileDownload(context.Background(), nil, slackFileDownloadInput{FileID: "F123"})
	if err != nil || res != nil {
		t.Fatalf("slackFileDownload returned result=%v err=%v", res, err)
	}
	want := slackFileDownloadOutput{
		OK: true, Workspace: "https://acme.slack.com", FileID: "F123", Name: "report.pdf",
		Mimetype: "application/pdf", Size: 8, Path: filepath.Join(root, "F123-report.pdf"),
	}
	if out != want {
		t.Fatalf("output = %+v, want %+v", out, want)
	}
	if strings.Join(calls, ",") != "info,download" {
		t.Fatalf("call order = %v", calls)
	}
	got, err := os.ReadFile(out.Path)
	if err != nil || string(got) != "%PDF-1.7" {
		t.Fatalf("saved file = %q, err=%v", got, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(out.Path); err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("saved file mode = %v, err=%v, want 0600", info.Mode().Perm(), err)
		}
	}
	if names := rootEntries(t, root); len(names) != 1 {
		t.Fatalf("download root holds %v, want only the saved file", names)
	}
	assertNoSecrets(t, out)
}

func TestSlackFileDownloadFallsBackToURLPrivateAndReplacesEarlierCopy(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "F123-report.pdf"), []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	h := downloadHandler(root, func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.test" {
			return response(req, 200, `{"ok":true,"file":{"id":"F123","name":"report.pdf","mimetype":"application/pdf","url_private":"https://files.slack.com/files-pri/T1-F123/report.pdf"}}`), nil
		}
		if req.URL.Path != "/files-pri/T1-F123/report.pdf" {
			t.Errorf("download path = %s, want url_private", req.URL.Path)
		}
		return response(req, 200, "fresh"), nil
	})
	res, out, err := h.slackFileDownload(context.Background(), nil, slackFileDownloadInput{FileID: "F123"})
	if err != nil || res != nil {
		t.Fatalf("slackFileDownload returned result=%v err=%v", res, err)
	}
	if got, _ := os.ReadFile(out.Path); string(got) != "fresh" {
		t.Fatalf("saved file = %q, want the new download", got)
	}
}

func TestSlackFileDownloadRejectsDisabledOrInvalidInputBeforeSlack(t *testing.T) {
	calls := 0
	h := &handlers{credsFn: func() (slacktokens.Result, error) { calls++; return testResult(), nil }}
	cases := []struct {
		name, root, fileID string
	}{
		{"root unset", "", "F123"},
		{"relative root", "relative-root", "F123"},
		{"missing root", filepath.Join(t.TempDir(), "missing"), "F123"},
		{"empty id", t.TempDir(), ""},
		{"traversal id", t.TempDir(), "../F123"},
		{"separator id", t.TempDir(), "F1/23"},
		{"lowercase id", t.TempDir(), "f123"},
		{"not a file id", t.TempDir(), "C123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h.cfg.downloadRoot = tc.root
			res, _, err := h.slackFileDownload(context.Background(), nil, slackFileDownloadInput{FileID: tc.fileID})
			if err != nil || res == nil || !res.IsError {
				t.Fatalf("result=%v err=%v, want tool error", res, err)
			}
		})
	}
	if calls != 0 {
		t.Fatalf("rejected downloads made %d Slack credential lookups", calls)
	}
}

func TestSlackFileDownloadPropagatesFilesInfoError(t *testing.T) {
	h := downloadHandler(t.TempDir(), func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api.test" {
			t.Errorf("downloaded after files.info failed: %s", req.URL)
		}
		return response(req, 200, `{"ok":false,"error":"file_not_found"}`), nil
	})
	res, _, err := h.slackFileDownload(context.Background(), nil, slackFileDownloadInput{FileID: "F123"})
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("result=%v err=%v, want tool error", res, err)
	}
	serialized, _ := json.Marshal(res)
	if !strings.Contains(string(serialized), "slack could not read file info: file_not_found") {
		t.Fatalf("files.info error lost: %s", serialized)
	}
}

func TestSlackFileDownloadRefusesUntrustedFilesWithoutSendingSession(t *testing.T) {
	cases := map[string]string{
		"external host": `{"ok":true,"file":{"id":"F123","name":"a.pdf","url_private":"https://evil.example/a.pdf"}}`,
		"is_external":   `{"ok":true,"file":{"id":"F123","name":"a.pdf","is_external":true,"url_private":"https://files.slack.com/files-pri/T1-F123/a.pdf"}}`,
		"http":          `{"ok":true,"file":{"id":"F123","name":"a.pdf","url_private_download":"http://files.slack.com/files-pri/T1-F123/download/a.pdf"}}`,
		"look-alike":    `{"ok":true,"file":{"id":"F123","name":"a.pdf","url_private_download":"https://files.slack.com.evil.example/files-pri/T1-F123/download/a.pdf"}}`,
		"no URL":        `{"ok":true,"file":{"id":"F123","name":"a.pdf"}}`,
		"other file":    `{"ok":true,"file":{"id":"F999","name":"a.pdf","url_private_download":"https://files.slack.com/files-pri/T1-F999/download/a.pdf"}}`,
		"over limit":    `{"ok":true,"file":{"id":"F123","name":"a.pdf","size":1073741825,"url_private_download":"https://files.slack.com/files-pri/T1-F123/download/a.pdf"}}`,
	}
	for name, info := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			h := downloadHandler(root, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host != "api.test" {
					t.Errorf("session sent to %s", req.URL)
				}
				return response(req, 200, info), nil
			})
			res, _, err := h.slackFileDownload(context.Background(), nil, slackFileDownloadInput{FileID: "F123"})
			if err != nil || res == nil || !res.IsError {
				t.Fatalf("result=%v err=%v, want tool error", res, err)
			}
			serialized, _ := json.Marshal(res)
			if strings.Contains(string(serialized), "evil.example") {
				t.Fatalf("untrusted URL reached tool result: %s", serialized)
			}
			if names := rootEntries(t, root); len(names) != 0 {
				t.Fatalf("download root holds %v after a refused download", names)
			}
		})
	}
}

func TestValidateSlackFileURL(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		workspace string
		wantErr   bool
	}{
		{"commercial", testFileURL, "https://acme.slack.com", false},
		{"enterprise workspace", testFileURL, "https://acme.enterprise.slack.com", false},
		{"gov", "https://files.slack-gov.com/files-pri/T1-F1/a.pdf", "https://acme.slack-gov.com", false},
		{"upper-case host", "https://FILES.SLACK.COM/files-pri/T1-F1/a.pdf", "https://acme.slack.com", false},
		{"wrong host", "https://evil.example/files-pri/T1-F1/a.pdf", "https://acme.slack.com", true},
		{"api host", "https://slack.com/files-pri/T1-F1/a.pdf", "https://acme.slack.com", true},
		{"workspace host", "https://acme.slack.com/files-pri/T1-F1/a.pdf", "https://acme.slack.com", true},
		{"suffix look-alike", "https://files.slack.com.evil.example/a.pdf", "https://acme.slack.com", true},
		{"prefix look-alike", "https://evilfiles.slack.com/a.pdf", "https://acme.slack.com", true},
		{"trailing dot", "https://files.slack.com./a.pdf", "https://acme.slack.com", true},
		{"http", "http://files.slack.com/files-pri/T1-F1/a.pdf", "https://acme.slack.com", true},
		{"userinfo", "https://files.slack.com@evil.example/a.pdf", "https://acme.slack.com", true},
		{"userinfo on Slack host", "https://user@files.slack.com/a.pdf", "https://acme.slack.com", true},
		{"explicit port", "https://files.slack.com:8443/a.pdf", "https://acme.slack.com", true},
		{"cross family", "https://files.slack.com/a.pdf", "https://acme.slack-gov.com", true},
		{"relative", "/files-pri/T1-F1/a.pdf", "https://acme.slack.com", true},
		{"empty", "", "https://acme.slack.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSlackFileURL(tc.raw, tc.workspace)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateSlackFileURL() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestSlackFileDownloadFollowsRedirectOnSlackFileHost(t *testing.T) {
	root := t.TempDir()
	var hops []string
	h := downloadHandler(root, func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.test" {
			return response(req, 200, fileInfoBody(testFileURL)), nil
		}
		hops = append(hops, req.URL.Path)
		if req.Header.Get("Authorization") != "Bearer "+testXOXC || req.Header.Get("Cookie") == "" {
			t.Errorf("hop %s lost the session", req.URL.Path)
		}
		if req.URL.Path == "/moved/report.pdf" {
			return response(req, 200, "%PDF-1.7"), nil
		}
		resp := response(req, http.StatusFound, "")
		resp.Header.Set("Location", "https://files.slack.com/moved/report.pdf")
		return resp, nil
	})
	res, out, err := h.slackFileDownload(context.Background(), nil, slackFileDownloadInput{FileID: "F123"})
	if err != nil || res != nil {
		t.Fatalf("slackFileDownload returned result=%v err=%v", res, err)
	}
	if len(hops) != 2 || out.Size != 8 {
		t.Fatalf("hops = %v, output = %+v", hops, out)
	}
}

func TestSlackFileDownloadRefusesRedirectOffSlackFileHost(t *testing.T) {
	for _, location := range []string{
		"https://evil.example/collect",
		"http://files.slack.com/files-pri/T1-F123/report.pdf",
		"https://files.slack.com.evil.example/collect",
		"https://files.slack.com:8443/collect",
	} {
		t.Run(location, func(t *testing.T) {
			root := t.TempDir()
			fileHostCalls := 0
			h := downloadHandler(root, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "api.test" {
					return response(req, 200, fileInfoBody(testFileURL)), nil
				}
				if req.URL.String() != testFileURL {
					t.Errorf("followed a redirect to %s", req.URL)
				}
				fileHostCalls++
				resp := response(req, http.StatusFound, "")
				resp.Header.Set("Location", location)
				return resp, nil
			})
			res, _, err := h.slackFileDownload(context.Background(), nil, slackFileDownloadInput{FileID: "F123"})
			if err != nil || res == nil || !res.IsError {
				t.Fatalf("result=%v err=%v, want tool error", res, err)
			}
			if fileHostCalls != 1 {
				t.Fatalf("file host calls = %d, want 1", fileHostCalls)
			}
			serialized, _ := json.Marshal(res)
			if strings.Contains(string(serialized), "evil.example") || strings.Contains(string(serialized), "collect") {
				t.Fatalf("redirect target reached tool result: %s", serialized)
			}
			assertNoSecrets(t, res)
			if names := rootEntries(t, root); len(names) != 0 {
				t.Fatalf("download root holds %v after a refused redirect", names)
			}
		})
	}
}

func TestSlackFileDownloadRejectsHTMLInsteadOfFile(t *testing.T) {
	root := t.TempDir()
	h := downloadHandler(root, func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.test" {
			return response(req, 200, fileInfoBody(testFileURL)), nil
		}
		resp := response(req, 200, "<!DOCTYPE html><title>Sign in</title>")
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
		return resp, nil
	})
	res, _, err := h.slackFileDownload(context.Background(), nil, slackFileDownloadInput{FileID: "F123"})
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("result=%v err=%v, want tool error", res, err)
	}
	if names := rootEntries(t, root); len(names) != 0 {
		t.Fatalf("download root holds %v after an HTML response", names)
	}
}

func TestSlackFileDownloadTransferErrorsKeepCauseAndOmitSecrets(t *testing.T) {
	for name, transfer := range map[string]roundTripFunc{
		"network": func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection reset by peer")
		},
		"status": func(req *http.Request) (*http.Response, error) {
			return response(req, http.StatusForbidden, testXOXC), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			h := downloadHandler(root, func(req *http.Request) (*http.Response, error) {
				if req.URL.Host == "api.test" {
					return response(req, 200, fileInfoBody(testFileURL)), nil
				}
				return transfer(req)
			})
			res, _, err := h.slackFileDownload(context.Background(), nil, slackFileDownloadInput{FileID: "F123"})
			if err != nil || res == nil || !res.IsError {
				t.Fatalf("result=%v err=%v, want tool error", res, err)
			}
			serialized, _ := json.Marshal(res)
			if !strings.Contains(string(serialized), "connection reset by peer") && !strings.Contains(string(serialized), "HTTP status 403") {
				t.Fatalf("transfer error lost its cause: %s", serialized)
			}
			if strings.Contains(string(serialized), "files-pri") {
				t.Fatalf("file URL reached tool result: %s", serialized)
			}
			assertNoSecrets(t, res)
			if names := rootEntries(t, root); len(names) != 0 {
				t.Fatalf("download root holds %v after a failed transfer", names)
			}
		})
	}
}

func TestSlackFileDownloadConfinesHostileNameToRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "downloads")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	h := downloadHandler(root, func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "api.test" {
			return response(req, 200, `{"ok":true,"file":{"id":"F123","name":"../../escape.txt","url_private_download":"`+testFileURL+`"}}`), nil
		}
		return response(req, 200, "data"), nil
	})
	res, out, err := h.slackFileDownload(context.Background(), nil, slackFileDownloadInput{FileID: "F123"})
	if err != nil || res != nil {
		t.Fatalf("slackFileDownload returned result=%v err=%v", res, err)
	}
	if filepath.Dir(out.Path) != root {
		t.Fatalf("saved to %s, outside %s", out.Path, root)
	}
	if names := rootEntries(t, parent); len(names) != 1 || names[0] != "downloads" {
		t.Fatalf("parent of the download root holds %v", names)
	}
}

func TestSaveDownloadReplacesSymlinkWithoutWritingThroughIt(t *testing.T) {
	rootDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootDir, "F123-a.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := saveDownload(root, "F123-a.txt", strings.NewReader("new"), maxDownloadBytes); err != nil {
		t.Fatalf("saveDownload: %v", err)
	}
	if got, _ := os.ReadFile(outside); string(got) != "secret" {
		t.Fatalf("wrote through a symlink to outside the root: %q", got)
	}
	info, err := os.Lstat(filepath.Join(rootDir, "F123-a.txt"))
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("saved entry is not a regular file: %v, err=%v", info, err)
	}
}

func TestSaveDownloadEnforcesLimitAndLeavesNoPartialFile(t *testing.T) {
	rootDir := t.TempDir()
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if n, err := saveDownload(root, "F123-a.txt", strings.NewReader("1234"), 4); err != nil || n != 4 {
		t.Fatalf("saveDownload at the limit = %d, %v", n, err)
	}
	if _, err := saveDownload(root, "F123-b.txt", strings.NewReader("12345"), 4); err == nil || !strings.Contains(err.Error(), "1 GiB") {
		t.Fatalf("saveDownload over the limit error = %v", err)
	}
	if _, err := saveDownload(root, "F123-c.txt", &failingReader{}, 4); err == nil {
		t.Fatal("saveDownload ignored a read error")
	}
	if names := rootEntries(t, rootDir); len(names) != 1 || names[0] != "F123-a.txt" {
		t.Fatalf("download root holds %v, want only the complete file", names)
	}
}

type failingReader struct{}

func (*failingReader) Read([]byte) (int, error) { return 0, errors.New("stream broke") }

func TestDownloadFileName(t *testing.T) {
	long := strings.Repeat("報", 100) + ".pdf"
	cases := []struct {
		name, want string
	}{
		{"report.pdf", "F123-report.pdf"},
		{"報告書 v2.pdf", "F123-報告書 v2.pdf"},
		{"../../etc/passwd", "F123-.._.._etc_passwd"},
		{`a\b:c*d?e"f<g>h|i`, "F123-a_b_c_d_e_f_g_h_i"},
		{"line\nbreak\x00.txt", "F123-line_break_.txt"},
		{"trailing. . ", "F123-trailing"},
		{"...", "F123"},
		{"", "F123"},
		{"bad\xffutf8.txt", "F123-bad_utf8.txt"},
	}
	for _, tc := range cases {
		if got := downloadFileName("F123", tc.name); got != tc.want {
			t.Errorf("downloadFileName(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
	got := downloadFileName("F123", long)
	if len(got) > maxDownloadNameBytes || !utf8.ValidString(got) || !strings.HasSuffix(got, ".pdf") || !strings.HasPrefix(got, "F123-報") {
		t.Fatalf("long name = %q (%d bytes)", got, len(got))
	}
}

func TestFileDownloadToolDescriptionReflectsRoot(t *testing.T) {
	if d := fileDownloadToolDescription(mcpConfig{}); !strings.Contains(d, downloadRootEnv+" is not configured") {
		t.Errorf("description without a root = %q", d)
	}
	if d := fileDownloadToolDescription(mcpConfig{downloadRoot: "/data"}); !strings.Contains(d, "1 GiB") {
		t.Errorf("description with a root = %q", d)
	}
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	uploadRootEnv       = "SLACKTOKENS_MCP_UPLOAD_ROOT"
	slackFileUploadURL  = "files.getUploadURLExternal"
	slackFileComplete   = "files.completeUploadExternal"
	maxUploadBytes      = int64(1 << 30)
	slackUploadTimeout  = 10 * time.Minute
	maxUploadErrorBytes = 4096
)

type slackFileUploadInput struct {
	RelativePath   string `json:"relative_path" jsonschema:"File path relative to SLACKTOKENS_MCP_UPLOAD_ROOT. Absolute paths and paths outside the configured root are rejected."`
	Workspace      string `json:"workspace,omitempty" jsonschema:"Slack workspace URL to act as, e.g. https://acme.slack.com. Omit when only one workspace is signed in."`
	ChannelID      string `json:"channel_id" jsonschema:"Slack channel ID where the file will be shared. Required; private unshared uploads are not created."`
	ThreadTS       string `json:"thread_ts,omitempty" jsonschema:"Optional parent message timestamp to share the file as a thread reply."`
	Title          string `json:"title,omitempty" jsonschema:"Optional title shown for the uploaded file. Defaults to the local filename."`
	InitialComment string `json:"initial_comment,omitempty" jsonschema:"Optional message text to include with the file in the channel."`
}

type slackFileUploadOutput struct {
	OK        bool   `json:"ok" jsonschema:"Whether Slack accepted and shared the file."`
	Workspace string `json:"workspace" jsonschema:"The workspace the file was shared to."`
	ChannelID string `json:"channel_id" jsonschema:"The Slack channel where the file was shared."`
	FileID    string `json:"file_id" jsonschema:"Slack file ID."`
	Filename  string `json:"filename" jsonschema:"The uploaded filename."`
	Title     string `json:"title" jsonschema:"The title used for the uploaded file."`
}

func fileUploadInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"relative_path":   {Type: "string", Description: "File path relative to SLACKTOKENS_MCP_UPLOAD_ROOT. Absolute paths and paths outside the configured root are rejected."},
			"workspace":       {Type: "string", Description: "Slack workspace URL. Omit when only one workspace is signed in."},
			"channel_id":      {Type: "string", Description: "Slack channel ID where the file will be shared."},
			"thread_ts":       {Type: "string", Description: "Optional parent message timestamp to share the file as a thread reply."},
			"title":           {Type: "string", Description: "Optional title. Defaults to the local filename."},
			"initial_comment": {Type: "string", Description: "Optional message text to include with the file."},
		},
		Required:             []string{"relative_path", "channel_id"},
		AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}},
	}
}

func fileUploadToolDescription(cfg mcpConfig) string {
	var b strings.Builder
	b.WriteString("Uploads one local file to Slack and shares it in a channel. The file is read only from the directory configured by ")
	b.WriteString(uploadRootEnv)
	b.WriteString("; pass a relative_path within that directory. The channel_id is required. The Slack upload ticket URL stays inside this server and is never returned to the AI. ")
	if cfg.allowWrite {
		b.WriteString("Writes are ENABLED by ")
	} else {
		b.WriteString("Writes are disabled; set ")
	}
	b.WriteString(allowWriteEnv)
	b.WriteString("=1 to enable file uploads. ")
	if cfg.uploadRoot == "" {
		b.WriteString(uploadRootEnv)
		b.WriteString(" is not configured, so uploads will fail until it points to an existing directory.")
	} else {
		b.WriteString("Files larger than 1 GiB are rejected.")
	}
	return b.String()
}

type slackUploadTicket struct {
	OK        bool   `json:"ok"`
	UploadURL string `json:"upload_url"`
	FileID    string `json:"file_id"`
}

type slackMethodError struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func (h *handlers) slackFileUpload(ctx context.Context, _ *mcp.CallToolRequest, in slackFileUploadInput) (*mcp.CallToolResult, slackFileUploadOutput, error) {
	if !h.cfg.allowWrite {
		return errorResult(fmt.Errorf("file upload is disabled; set %s=1 to enable write methods", allowWriteEnv)), slackFileUploadOutput{}, nil
	}
	if h.cfg.uploadRoot == "" {
		return errorResult(errors.New("file upload is disabled because the upload root is not configured")), slackFileUploadOutput{}, nil
	}
	if strings.TrimSpace(in.ChannelID) == "" {
		return errorResult(errors.New("channel_id is required")), slackFileUploadOutput{}, nil
	}
	if in.ThreadTS != "" && strings.ContainsAny(in.ThreadTS, "\r\n") {
		return errorResult(errors.New("thread_ts contains invalid characters")), slackFileUploadOutput{}, nil
	}

	f, filename, size, closeFile, err := h.openUploadFile(in.RelativePath)
	if err != nil {
		return errorResult(err), slackFileUploadOutput{}, nil
	}
	defer closeFile()

	title := in.Title
	if title == "" {
		title = filename
	}
	getParams := map[string]any{"filename": filename, "length": size}
	res, getOut := h.call(ctx, in.Workspace, slackFileUploadURL, getParams)
	if res != nil {
		return res, slackFileUploadOutput{}, nil
	}
	if !getOut.OK {
		return errorResult(slackMethodFailure("request upload URL", getOut.Body)), slackFileUploadOutput{}, nil
	}
	var ticket slackUploadTicket
	if err := json.Unmarshal([]byte(getOut.Body), &ticket); err != nil || ticket.UploadURL == "" || ticket.FileID == "" {
		return errorResult(errors.New("Slack returned an invalid upload ticket")), slackFileUploadOutput{}, nil
	}
	if err := validateSlackUploadURL(ticket.UploadURL, getOut.Workspace); err != nil {
		return errorResult(errors.New("Slack returned an untrusted upload URL")), slackFileUploadOutput{}, nil
	}
	if err := h.uploadFile(ctx, ticket.UploadURL, f, size); err != nil {
		return errorResult(err), slackFileUploadOutput{}, nil
	}

	fileEntry := map[string]any{"id": ticket.FileID, "title": title}
	completeParams := map[string]any{
		"files":      []any{fileEntry},
		"channel_id": in.ChannelID,
	}
	if in.ThreadTS != "" {
		completeParams["thread_ts"] = in.ThreadTS
	}
	if in.InitialComment != "" {
		completeParams["initial_comment"] = in.InitialComment
	}
	res, completeOut := h.call(ctx, getOut.Workspace, slackFileComplete, completeParams)
	if res != nil {
		return res, slackFileUploadOutput{}, nil
	}
	if !completeOut.OK {
		return errorResult(slackMethodFailure("share uploaded file", completeOut.Body)), slackFileUploadOutput{}, nil
	}
	return nil, slackFileUploadOutput{
		OK:        true,
		Workspace: completeOut.Workspace,
		ChannelID: in.ChannelID,
		FileID:    ticket.FileID,
		Filename:  filename,
		Title:     title,
	}, nil
}

func (h *handlers) openUploadFile(relativePath string) (*os.File, string, int64, func(), error) {
	if !fs.ValidPath(relativePath) || strings.Contains(relativePath, `\`) || filepath.IsAbs(filepath.FromSlash(relativePath)) || filepath.VolumeName(filepath.FromSlash(relativePath)) != "" {
		return nil, "", 0, nil, errors.New("relative_path must name a file inside the configured upload root")
	}
	rootPath, err := filepath.Abs(h.cfg.uploadRoot)
	if err != nil {
		return nil, "", 0, nil, errors.New("cannot resolve configured upload root")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, "", 0, nil, errors.New("cannot open configured upload root")
	}
	f, err := root.Open(filepath.FromSlash(relativePath))
	if err != nil {
		_ = root.Close()
		return nil, "", 0, nil, errors.New("cannot open file inside configured upload root")
	}
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() {
		_ = f.Close()
		_ = root.Close()
		return nil, "", 0, nil, errors.New("relative_path must refer to a regular file")
	}
	if stat.Size() <= 0 {
		_ = f.Close()
		_ = root.Close()
		return nil, "", 0, nil, errors.New("empty files cannot be uploaded")
	}
	if stat.Size() > maxUploadBytes {
		_ = f.Close()
		_ = root.Close()
		return nil, "", 0, nil, fmt.Errorf("file exceeds the 1 GiB upload limit")
	}
	return f, filepath.Base(relativePath), stat.Size(), func() {
		_ = f.Close()
		_ = root.Close()
	}, nil
}

func validateSlackUploadURL(raw, workspace string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" {
		return errors.New("invalid URL")
	}
	workspaceHost := hostOf(workspace)
	expectedHost := "files.slack.com"
	if strings.HasSuffix(workspaceHost, ".slack-gov.com") || workspaceHost == "slack-gov.com" {
		expectedHost = "files.slack-gov.com"
	}
	if !strings.EqualFold(u.Hostname(), expectedHost) || !strings.HasPrefix(u.EscapedPath(), "/upload/v1/") || len(u.EscapedPath()) <= len("/upload/v1/") {
		return errors.New("unexpected upload endpoint")
	}
	return nil
}

func (h *handlers) uploadClient() *http.Client {
	client := &http.Client{Timeout: slackUploadTimeout}
	if h.httpClient != nil {
		copy := *h.httpClient
		client = &copy
		if client.Timeout == 0 {
			client.Timeout = slackUploadTimeout
		}
	}
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

func (h *handlers) uploadFile(ctx context.Context, uploadURL string, file io.Reader, size int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, file)
	if err != nil {
		return errors.New("could not create Slack file transfer request")
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "slacktokens-mcp/"+version)
	resp, err := h.uploadClient().Do(req)
	if err != nil {
		return errors.New("Slack file transfer failed")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxUploadErrorBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Slack file transfer failed with HTTP status %d", resp.StatusCode)
	}
	return nil
}

func slackMethodFailure(operation, body string) error {
	var apiErr slackMethodError
	if json.Unmarshal([]byte(body), &apiErr) == nil && apiErr.Error != "" {
		for _, r := range apiErr.Error {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
				return fmt.Errorf("Slack could not %s", operation)
			}
		}
		return fmt.Errorf("Slack could not %s: %s", operation, apiErr.Error)
	}
	return fmt.Errorf("Slack could not %s", operation)
}

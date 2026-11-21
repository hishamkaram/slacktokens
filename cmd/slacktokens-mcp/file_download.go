// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	downloadRootEnv      = "SLACKTOKENS_MCP_DOWNLOAD_ROOT"
	slackFileInfo        = "files.info"
	maxDownloadBytes     = int64(1 << 30)
	maxDownloadHops      = 5
	maxDownloadNameBytes = 200
)

// fileIDPattern is the shape of a Slack file ID (e.g. F0123ABCDEF). Checking it
// before any Slack call also keeps the ID safe to use in a local filename.
var fileIDPattern = regexp.MustCompile(`^F[A-Z0-9]{1,39}$`)

type slackFileDownloadInput struct {
	FileID    string `json:"file_id" jsonschema:"Slack file ID, e.g. F0123ABCDEF, from a message's files[].id."`
	Workspace string `json:"workspace,omitempty" jsonschema:"Slack workspace URL to act as, e.g. https://acme.slack.com. Omit when only one workspace is signed in."`
}

type slackFileDownloadOutput struct {
	OK        bool   `json:"ok" jsonschema:"Whether the file was saved."`
	Workspace string `json:"workspace" jsonschema:"The workspace the file was read from."`
	FileID    string `json:"file_id" jsonschema:"Slack file ID."`
	Name      string `json:"name" jsonschema:"The file's name in Slack."`
	Mimetype  string `json:"mimetype" jsonschema:"The file's MIME type as reported by Slack."`
	Size      int64  `json:"size" jsonschema:"Number of bytes saved."`
	Path      string `json:"path" jsonschema:"Absolute local path of the saved file, inside SLACKTOKENS_MCP_DOWNLOAD_ROOT."`
}

func fileDownloadInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"file_id":   {Type: "string", Description: "Slack file ID, e.g. F0123ABCDEF, from a message's files[].id."},
			"workspace": {Type: "string", Description: "Slack workspace URL. Omit when only one workspace is signed in."},
		},
		Required:             []string{"file_id"},
		AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}},
	}
}

func fileDownloadToolDescription(cfg mcpConfig) string {
	var b strings.Builder
	b.WriteString("Downloads one Slack file, such as a message attachment the signed-in user can already see, into the directory configured by ")
	b.WriteString(downloadRootEnv)
	b.WriteString(" and returns its local path. Pass the file_id from a message's files[].id. The server looks the file up with files.info and fetches it with your session server-side; credentials never reach the AI. ")
	b.WriteString("The file is saved as <file_id>-<name>, replacing an earlier download of the same file. ")
	if cfg.downloadRoot == "" {
		b.WriteString(downloadRootEnv)
		b.WriteString(" is not configured, so downloads will fail until it is set to an existing absolute directory path.")
	} else {
		b.WriteString("Files larger than 1 GiB are rejected.")
	}
	return b.String()
}

// slackFileInfoResponse is the part of a files.info response this tool reads
// (https://docs.slack.dev/reference/methods/files.info).
type slackFileInfoResponse struct {
	File struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		Mimetype           string `json:"mimetype"`
		Size               int64  `json:"size"`
		IsExternal         bool   `json:"is_external"`
		URLPrivate         string `json:"url_private"`
		URLPrivateDownload string `json:"url_private_download"`
	} `json:"file"`
}

func (h *handlers) slackFileDownload(ctx context.Context, _ *mcp.CallToolRequest, in slackFileDownloadInput) (*mcp.CallToolResult, slackFileDownloadOutput, error) {
	if h.cfg.downloadRoot == "" {
		return errorResult(errors.New("file download is disabled because the download root is not configured")), slackFileDownloadOutput{}, nil
	}
	// A relative root would resolve against whatever working directory the MCP
	// host chose, so the confinement boundary would depend on the host.
	if !filepath.IsAbs(h.cfg.downloadRoot) {
		return errorResult(fmt.Errorf("%s must be an absolute path", downloadRootEnv)), slackFileDownloadOutput{}, nil
	}
	if !fileIDPattern.MatchString(in.FileID) {
		return errorResult(errors.New("file_id must be a Slack file ID such as F0123ABCDEF")), slackFileDownloadOutput{}, nil
	}
	root, err := os.OpenRoot(h.cfg.downloadRoot)
	if err != nil {
		return errorResult(fmt.Errorf("cannot open configured download root: %w", pathErrorCause(err))), slackFileDownloadOutput{}, nil
	}
	defer func() { _ = root.Close() }()

	res, infoOut := h.call(ctx, in.Workspace, slackFileInfo, map[string]any{"file": in.FileID})
	if res != nil {
		return res, slackFileDownloadOutput{}, nil
	}
	if !infoOut.OK {
		return errorResult(slackMethodFailure("read file info", infoOut.Body)), slackFileDownloadOutput{}, nil
	}
	var info slackFileInfoResponse
	if err := json.Unmarshal([]byte(infoOut.Body), &info); err != nil || info.File.ID != in.FileID {
		return errorResult(errors.New("slack returned invalid file info")), slackFileDownloadOutput{}, nil
	}
	file := info.File
	if file.IsExternal {
		return errorResult(errors.New("file is hosted outside Slack and cannot be downloaded")), slackFileDownloadOutput{}, nil
	}
	if file.Size > maxDownloadBytes {
		return errorResult(errors.New("file exceeds the 1 GiB download limit")), slackFileDownloadOutput{}, nil
	}
	fileURL := file.URLPrivateDownload
	if fileURL == "" {
		fileURL = file.URLPrivate
	}
	if err := validateSlackFileURL(fileURL, infoOut.Workspace); err != nil {
		return errorResult(errors.New("slack returned an untrusted download URL")), slackFileDownloadOutput{}, nil
	}
	sess, err := h.session(infoOut.Workspace)
	if err != nil {
		return errorResult(err), slackFileDownloadOutput{}, nil
	}

	name := downloadFileName(file.ID, file.Name)
	size, err := h.downloadFile(ctx, root, sess, fileURL, name, file.Mimetype, file.Size)
	if err != nil {
		return errorResult(err), slackFileDownloadOutput{}, nil
	}
	return nil, slackFileDownloadOutput{
		OK:        true,
		Workspace: infoOut.Workspace,
		FileID:    file.ID,
		Name:      file.Name,
		Mimetype:  file.Mimetype,
		Size:      size,
		Path:      filepath.Join(h.cfg.downloadRoot, name),
	}, nil
}

// validateSlackFileURL accepts only a URL that the Slack session may be sent
// to. Slack's guide to downloading files says to check that the scheme is https
// and that the parsed host exactly matches a Slack file host such as
// files.slack.com before attaching credentials, because a remote file's
// url_private is the external URL its app supplied
// (https://docs.slack.dev/messaging/working-with-files#downloading-files).
func validateSlackFileURL(raw, workspace string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || !strings.EqualFold(u.Hostname(), slackFileHost(workspace)) {
		return errors.New("untrusted file URL")
	}
	return nil
}

// downloadClient returns a client for the credentialed file fetch. A redirect
// is followed only to a URL validateSlackFileURL accepts; CheckRedirect runs
// before the next request is sent, so the session is never sent anywhere else.
// The transfer deadline comes from the request context (see downloadFile).
func (h *handlers) downloadClient(workspace string) *http.Client {
	client := &http.Client{}
	if h.httpClient != nil {
		injected := *h.httpClient
		client = &injected
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxDownloadHops {
			return errors.New("too many redirects")
		}
		if validateSlackFileURL(req.URL.String(), workspace) != nil {
			return errors.New("refused a redirect away from the Slack file host")
		}
		return nil
	}
	return client
}

// downloadFile fetches fileURL with the session and saves the body as name in
// root. Slack's own size for the file only scales the deadline.
func (h *handlers) downloadFile(ctx context.Context, root *os.Root, sess slackSession, fileURL, name, mimetype string, size int64) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, uploadTimeout(size))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileURL, nil)
	if err != nil {
		return 0, errors.New("could not create Slack file download request")
	}
	req.Header.Set("Authorization", "Bearer "+sess.token)
	req.Header.Set("Cookie", sess.cookie)
	req.Header.Set("User-Agent", "slacktokens-mcp/"+version)
	resp, err := h.downloadClient(sess.workspace).Do(req)
	if err != nil {
		return 0, fmt.Errorf("slack file download failed: %w", transferErrorCause(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("slack file download failed with HTTP status %d", resp.StatusCode)
	}
	// A session Slack does not accept for the file can get a web page with
	// HTTP 200 instead of the bytes. Saving it under the file's name would hand
	// the AI the wrong content.
	if got, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); got == "text/html" && mimetype != "text/html" {
		return 0, errors.New("slack returned a web page instead of the file; the signed-in session may not have access to it")
	}
	return saveDownload(root, name, resp.Body, maxDownloadBytes)
}

// saveDownload streams r into name inside root. The bytes go to a new temporary
// file first and are renamed into place only when complete and within limit, so
// a failed download leaves no partial file. os.Root confines both names to the
// root, and O_EXCL never opens an existing file or symlink.
func saveDownload(root *os.Root, name string, r io.Reader, limit int64) (int64, error) {
	tmp := "." + rand.Text() + ".part"
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, fmt.Errorf("cannot create file in the configured download root: %w", pathErrorCause(err))
	}
	n, err := io.Copy(f, io.LimitReader(r, limit+1))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	switch {
	case err != nil:
		err = fmt.Errorf("slack file download failed: %w", transferErrorCause(pathErrorCause(err)))
	case n > limit:
		err = errors.New("file exceeds the 1 GiB download limit")
	default:
		if err = root.Rename(tmp, name); err != nil {
			err = fmt.Errorf("cannot save file in the configured download root: %w", pathErrorCause(err))
		}
	}
	if err != nil {
		_ = root.Remove(tmp)
		return 0, err
	}
	return n, nil
}

// downloadFileName builds a single, portable path component for a Slack file:
// "<fileID>-<name>". The ID prefix keeps it unique, non-empty and free of a
// leading dot. Path separators, characters Windows forbids and control
// characters become "_", and trailing dots and spaces are trimmed because
// Windows drops them. Long names are shortened, keeping the extension.
func downloadFileName(fileID, name string) string {
	safe := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(`/\:*?"<>|`, r) {
			return '_'
		}
		return r
	}, strings.ToValidUTF8(name, "_"))
	if room := maxDownloadNameBytes - len(fileID) - 1; len(safe) > room {
		ext := path.Ext(safe)
		if len(ext) > room/2 {
			ext = ""
		}
		safe = strings.ToValidUTF8(safe[:room-len(ext)], "") + ext
	}
	if safe = strings.TrimRight(safe, ". "); safe == "" {
		return fileID
	}
	return fileID + "-" + safe
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

package slacktokens

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const localConfigKey = "localConfig_v2"

// GetTokens returns a map keyed by Slack workspace URL containing the personal
// xoxc- token and the workspace's display name. Works whether Slack is running
// or quit: if the live LevelDB is locked, the directory is snapshot-copied to
// a temp location and read from there.
func GetTokens() (map[string]Workspace, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return nil, ErrUnsupportedOS
	}
	path, err := slackLevelDBPath()
	if err != nil {
		return nil, err
	}
	return readTokensFrom(path)
}

func readTokensFrom(path string) (map[string]Workspace, error) {
	out, err := openAndExtractTokens(path)
	if err == nil {
		return out, nil
	}
	if !errors.Is(err, ErrLocalStorageLocked) {
		return nil, err
	}
	// LevelDB is held by a running Slack. Snapshot-copy the directory and read
	// the copy — goleveldb's lock is per-file, so the copy opens cleanly.
	snap, snapErr := snapshotLevelDB(path)
	if snapErr != nil {
		return nil, fmt.Errorf("snapshot leveldb: %w", snapErr)
	}
	defer func() { _ = os.RemoveAll(snap) }()
	return openAndExtractTokens(snap)
}

func openAndExtractTokens(path string) (map[string]Workspace, error) {
	db, err := leveldb.OpenFile(path, &opt.Options{ReadOnly: true})
	if err != nil {
		if isLockError(err) {
			return nil, fmt.Errorf("%w: %w", ErrLocalStorageLocked, err)
		}
		return nil, fmt.Errorf("open leveldb at %s: %w", path, err)
	}
	defer func() { _ = db.Close() }()

	iter := db.NewIterator(nil, nil)
	defer iter.Release()

	keyMatch := []byte(localConfigKey)
	var raw []byte
	for iter.Next() {
		if bytes.Contains(iter.Key(), keyMatch) {
			raw = append(raw[:0], iter.Value()...)
			break
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterate leveldb: %w", err)
	}
	if raw == nil {
		return nil, ErrLocalConfigMissing
	}

	cfg, err := parseLocalConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLocalConfigParse, err)
	}

	teamsAny, ok := cfg["teams"]
	if !ok {
		return nil, fmt.Errorf("%w: missing teams field", ErrLocalConfigParse)
	}
	teams, ok := teamsAny.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: teams field is not an object", ErrLocalConfigParse)
	}

	out := make(map[string]Workspace, len(teams))
	for _, v := range teams {
		t, ok := v.(map[string]any)
		if !ok {
			continue
		}
		url, _ := t["url"].(string)
		token, _ := t["token"].(string)
		name, _ := t["name"].(string)
		if url == "" || token == "" {
			continue
		}
		out[url] = Workspace{Token: token, Name: name}
	}
	if len(out) == 0 {
		return nil, errors.New("slacktokens: localConfig_v2 has no teams with token+url")
	}
	return out, nil
}

// snapshotLevelDB copies the LevelDB directory at src to a fresh temp dir and
// returns its path. Caller must os.RemoveAll the returned dir. The LOCK file
// is intentionally skipped — goleveldb will create its own in the copy.
//
// LevelDB recovery handles partially-written log records, so a copy taken
// while Slack is mid-write is safe to open read-only.
func snapshotLevelDB(src string) (string, error) {
	dst, err := os.MkdirTemp("", "slacktokens-leveldb-")
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		_ = os.RemoveAll(dst)
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "LOCK" {
			continue
		}
		if err := copyFile(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
			_ = os.RemoveAll(dst)
			return "", err
		}
	}
	return dst, nil
}

// isLockError reports whether err looks like a LevelDB file-lock conflict —
// i.e. another process (Slack) holds the directory's LOCK file. goleveldb
// surfaces this as the underlying flock errno (EAGAIN/EWOULDBLOCK on
// macOS/Linux, ERROR_LOCK_VIOLATION on Windows) rather than a typed value.
func isLockError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "lock") ||
		strings.Contains(s, "resource temporarily unavailable") ||
		strings.Contains(s, "being used by another process")
}

func copyFile(src, dst string) error {
	// #nosec G304 -- src/dst are internal: src is a child of the LevelDB
	// directory enumerated via os.ReadDir, dst is a freshly created MkdirTemp.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	// #nosec G304 -- dst is a freshly created MkdirTemp path.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

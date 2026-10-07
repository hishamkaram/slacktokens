// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

package slacktokens

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const localConfigKey = "localConfig_v2"

// GetTokens returns a map keyed by Slack workspace URL containing the personal
// xoxc- token and the workspace's display name. Works whether Slack is running
// or quit: the profile's LevelDB is copied (through a pinned os.Root) into a
// private temp directory and read from there, so a running Slack's lock never
// blocks the read and symlinks cannot redirect it.
func GetTokens() (map[string]Workspace, error) {
	root, err := openProfileRoot(materializeOpts{levelDB: true})
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	tmp, cleanup, err := materialize(root, materializeOpts{levelDB: true})
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return openAndExtractTokens(filepath.Join(tmp, "Local Storage", "leveldb"))
}

// readTokensFrom opens a LevelDB localStorage directory and extracts tokens. It
// is a thin helper over openAndExtractTokens, retained for tests that stage a
// store directly.
func readTokensFrom(path string) (map[string]Workspace, error) {
	return openAndExtractTokens(path)
}

func openAndExtractTokens(path string) (map[string]Workspace, error) {
	db, err := leveldb.OpenFile(path, &opt.Options{ReadOnly: true})
	if err != nil {
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

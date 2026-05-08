// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package slacktokens

import (
	"path/filepath"
	"testing"

	"github.com/syndtr/goleveldb/leveldb"
)

// stageLevelDB writes a temporary Chromium-style LevelDB with one entry whose
// key contains "localConfig_v2" and value is the supplied bytes. Returns the
// LevelDB directory path.
func stageLevelDB(t *testing.T, value []byte) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "leveldb")
	stageLevelDBAt(t, dir, value)
	return dir
}

func stageLevelDBAt(t *testing.T, dir string, value []byte) {
	t.Helper()
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Mirror Chromium's localStorage map-key shape:
	//   '_' + origin + '\x00' + format-byte + key-name
	key := append([]byte("_https://app.slack.com\x00\x01"), []byte(localConfigKey)...)
	if err := db.Put(key, value, nil); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestReadTokensFrom_TwoTeams(t *testing.T) {
	json := `{"teams":{"T1":{"url":"https://a.slack.com","token":"xoxc-1","name":"A"},` +
		`"T2":{"url":"https://b.slack.com","token":"xoxc-2","name":"B"}}}`
	// Prefix with 0x01 (Latin-1 / ASCII) like Chromium does.
	dir := stageLevelDB(t, append([]byte{0x01}, []byte(json)...))

	got, err := readTokensFrom(dir)
	if err != nil {
		t.Fatalf("readTokensFrom: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 teams, got %d: %#v", len(got), got)
	}
	if got["https://a.slack.com"].Token != "xoxc-1" {
		t.Fatalf("team A token wrong: %#v", got["https://a.slack.com"])
	}
	if got["https://b.slack.com"].Name != "B" {
		t.Fatalf("team B name wrong: %#v", got["https://b.slack.com"])
	}
}

func TestReadTokensFrom_MissingLocalConfig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "leveldb")
	db, err := leveldb.OpenFile(dir, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Put([]byte("some-other-key"), []byte("v"), nil); err != nil {
		t.Fatalf("put: %v", err)
	}
	db.Close()

	if _, err := readTokensFrom(dir); err == nil {
		t.Fatal("expected ErrLocalConfigMissing")
	}
}

func TestReadTokensFrom_BadJSON(t *testing.T) {
	dir := stageLevelDB(t, []byte("\x01not json"))
	if _, err := readTokensFrom(dir); err == nil {
		t.Fatal("expected parse error")
	}
}

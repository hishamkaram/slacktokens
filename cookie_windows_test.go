// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

//go:build windows

package slacktokens

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func stageCookiesDBWindows(t *testing.T, dir string, key []byte, metaVersion int, host, plain string) {
	t.Helper()
	path := filepath.Join(dir, "Network", "Cookies")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=rwc", url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.Exec(`
		CREATE TABLE cookies (
			host_key TEXT NOT NULL,
			name TEXT NOT NULL,
			encrypted_value BLOB,
			is_secure INTEGER
		);
		CREATE TABLE meta (key TEXT, value TEXT);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES('version', ?)`, fmt.Sprintf("%d", metaVersion)); err != nil {
		t.Fatalf("meta: %v", err)
	}

	plaintext := []byte(plain)
	if metaVersion >= 24 {
		sum := sha256.Sum256([]byte(host))
		plaintext = append(sum[:], plaintext...)
	}
	enc := encryptCookieValueGCM(t, plaintext, key)
	if _, err := db.Exec(
		`INSERT INTO cookies(host_key, name, encrypted_value, is_secure) VALUES(?,?,?,1)`,
		host, "d", enc,
	); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

// encryptCookieValueGCM is a test helper producing v10-prefixed AES-256-GCM
// ciphertext that decryptCookieValueGCM can round-trip.
func encryptCookieValueGCM(t *testing.T, plaintext, key []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	iv := make([]byte, aead.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ct := aead.Seal(nil, iv, plaintext, nil)
	out := make([]byte, 0, 3+len(iv)+len(ct))
	out = append(out, []byte("v10")...)
	out = append(out, iv...)
	out = append(out, ct...)
	return out
}

func TestDecryptCookieValueGCM_RoundTrip_NoSHA(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc := encryptCookieValueGCM(t, []byte("xoxd-windows-test"), key)
	got, err := decryptCookieValueGCM(enc, key, ".slack.com", 0)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != "xoxd-windows-test" {
		t.Fatalf("got %q", got)
	}
}

func TestDecryptCookieValueGCM_RoundTrip_WithSHAPrefix(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xa0 + i)
	}
	const host = ".slack.com"
	const want = "xoxd-with-sha"
	sum := sha256.Sum256([]byte(host))
	plaintext := append(sum[:], []byte(want)...)
	enc := encryptCookieValueGCM(t, plaintext, key)
	got, err := decryptCookieValueGCM(enc, key, host, 24)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDecryptCookieValueGCM_V20Rejected(t *testing.T) {
	key := make([]byte, 32)
	enc := append([]byte("v20"), make([]byte, 32)...)
	if _, err := decryptCookieValueGCM(enc, key, ".slack.com", 0); err == nil {
		t.Fatal("expected error for v20 prefix")
	}
}

func TestDecryptCookieValueGCM_UnknownPrefix(t *testing.T) {
	key := make([]byte, 32)
	enc := append([]byte("v99"), make([]byte, 32)...)
	if _, err := decryptCookieValueGCM(enc, key, ".slack.com", 0); err == nil {
		t.Fatal("expected error for unknown prefix")
	}
}

func TestDecryptCookieValueGCM_TamperedTagFails(t *testing.T) {
	key := make([]byte, 32)
	enc := encryptCookieValueGCM(t, []byte("data"), key)
	enc[len(enc)-1] ^= 0xff
	if _, err := decryptCookieValueGCM(enc, key, ".slack.com", 0); err == nil {
		t.Fatal("expected GCM auth failure on tampered tag")
	}
}

func TestReadLocalStateMasterKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Local State")

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(0x42 + i)
	}
	wrappedNoPrefix := []byte("FAKE-WRAPPED-KEY")
	full := append([]byte("DPAPI"), wrappedNoPrefix...)
	stateJSON, err := json.Marshal(map[string]any{
		"os_crypt": map[string]any{
			"encrypted_key": base64.StdEncoding.EncodeToString(full),
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, stateJSON, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	prev := dpapiUnprotectFn
	defer func() { dpapiUnprotectFn = prev }()
	dpapiUnprotectFn = func(in []byte) ([]byte, error) {
		if string(in) != string(wrappedNoPrefix) {
			t.Fatalf("dpapi got %q want %q", in, wrappedNoPrefix)
		}
		return masterKey, nil
	}

	got, err := readLocalStateMasterKey(path)
	if err != nil {
		t.Fatalf("readLocalStateMasterKey: %v", err)
	}
	if string(got) != string(masterKey) {
		t.Fatalf("master key mismatch: got %x", got)
	}
}

func TestReadLocalStateMasterKey_MissingDPAPIPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Local State")
	stateJSON, _ := json.Marshal(map[string]any{
		"os_crypt": map[string]any{
			"encrypted_key": base64.StdEncoding.EncodeToString([]byte("NOT-DPAPI-AT-ALL")),
		},
	})
	if err := os.WriteFile(path, stateJSON, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := readLocalStateMasterKey(path); err == nil {
		t.Fatal("expected error for missing DPAPI prefix")
	}
}

func TestMockIntegrationWindows_FullPipeline(t *testing.T) {
	profile := t.TempDir()
	t.Setenv(profileDirEnv, profile)

	// LevelDB with one workspace.
	cfg := `{"teams":{"T1":{"url":"https://a.slack.com","token":"xoxc-1","name":"A"}}}`
	dbDir := filepath.Join(profile, "Local Storage", "leveldb")
	if err := os.MkdirAll(filepath.Dir(dbDir), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	stageLevelDBAt(t, dbDir, append([]byte{0x01}, []byte(cfg)...))

	// Pretend Local State holds a DPAPI-wrapped 32-byte key. The test seam
	// returns the unwrapped key directly so we don't need real DPAPI.
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 1)
	}
	statePath := filepath.Join(profile, "Local State")
	stateJSON, _ := json.Marshal(map[string]any{
		"os_crypt": map[string]any{
			"encrypted_key": base64.StdEncoding.EncodeToString(append([]byte("DPAPI"), []byte("opaque")...)),
		},
	})
	if err := os.WriteFile(statePath, stateJSON, 0o600); err != nil {
		t.Fatalf("write Local State: %v", err)
	}
	prev := dpapiUnprotectFn
	defer func() { dpapiUnprotectFn = prev }()
	dpapiUnprotectFn = func(_ []byte) ([]byte, error) { return masterKey, nil }

	// Stage a Cookies SQLite with one v10 cookie under .slack.com,
	// meta.version=24, encrypted with masterKey + GCM + SHA-256(host) prefix.
	stageCookiesDBWindows(t, profile, masterKey, 24, ".slack.com", "xoxd-windows")

	res, err := GetTokensAndCookie()
	if err != nil {
		t.Fatalf("GetTokensAndCookie: %v", err)
	}
	if len(res.Tokens) != 1 {
		t.Fatalf("want 1 token, got %d", len(res.Tokens))
	}
	if res.Cookie.Name != "d" || res.Cookie.Value != "xoxd-windows" {
		t.Fatalf("cookie wrong: %#v", res.Cookie)
	}
}

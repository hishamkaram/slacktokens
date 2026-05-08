package slacktokens

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	_ "modernc.org/sqlite"
)

// stageCookiesDB writes a Chromium-shaped Cookies SQLite at <dir>/Cookies
// containing an encrypted `d` cookie keyed by the supplied key. metaVersion
// determines whether the SHA-256(host_key) prefix is prepended to plaintext.
func stageCookiesDB(t *testing.T, dir string, key []byte, metaVersion int, plain string) string {
	t.Helper()
	path := filepath.Join(dir, "Cookies")
	dsn := fmt.Sprintf("file:%s?mode=rwc", url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	if _, err := db.Exec(`
		CREATE TABLE cookies (
			host_key TEXT NOT NULL,
			name TEXT NOT NULL,
			encrypted_value BLOB,
			is_secure INTEGER
		);
		CREATE TABLE meta (key TEXT, value TEXT);
	`); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	if _, err := db.Exec(`INSERT INTO meta(key, value) VALUES('version', ?)`, fmt.Sprintf("%d", metaVersion)); err != nil {
		t.Fatalf("insert meta: %v", err)
	}

	host := ".slack.com"
	plaintext := []byte(plain)
	if metaVersion >= 24 {
		sum := sha256.Sum256([]byte(host))
		plaintext = append(sum[:], plaintext...)
	}
	enc, err := encryptCookieValueV10(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO cookies(host_key, name, encrypted_value, is_secure) VALUES(?,?,?,1)`,
		host, "d", enc,
	); err != nil {
		t.Fatalf("insert cookie: %v", err)
	}
	return path
}

func TestMockIntegration_FullPipeline(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("only macOS and Linux are supported")
	}

	profile := t.TempDir()
	t.Setenv(profileDirEnv, profile)

	// LevelDB store with two workspaces.
	json := `{"teams":{"T1":{"url":"https://a.slack.com","token":"xoxc-1","name":"A"},` +
		`"T2":{"url":"https://b.slack.com","token":"xoxc-2","name":"B"}}}`
	dbDir := filepath.Join(profile, "Local Storage", "leveldb")
	if err := os.MkdirAll(filepath.Dir(dbDir), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	stageLevelDBAt(t, dbDir, append([]byte{0x01}, []byte(json)...))

	// Override keychain seam to a deterministic password.
	const testPassword = "test-password-for-mock"
	prev := keychainPasswordFn
	keychainPasswordFn = func() (string, error) { return testPassword, nil }
	defer func() { keychainPasswordFn = prev }()

	// Use the platform's actual key derivation so encryption matches what
	// platformCookieKeys() will produce at decrypt time.
	keyV10, _, err := platformCookieKeys()
	if err != nil {
		t.Fatalf("platformCookieKeys: %v", err)
	}
	stageCookiesDB(t, profile, keyV10, 24, "xoxd-test")

	res, err := GetTokensAndCookie()
	if err != nil {
		t.Fatalf("GetTokensAndCookie: %v", err)
	}
	if len(res.Tokens) != 2 {
		t.Fatalf("want 2 tokens, got %d: %#v", len(res.Tokens), res.Tokens)
	}
	if res.Cookie.Name != "d" || res.Cookie.Value != "xoxd-test" {
		t.Fatalf("cookie wrong: %#v", res.Cookie)
	}
	if len(res.Cookies) != 1 {
		t.Fatalf("want 1 cookie in slice, got %d", len(res.Cookies))
	}
}

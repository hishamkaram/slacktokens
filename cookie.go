package slacktokens

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"strconv"

	_ "modernc.org/sqlite"
)

// keychainPasswordFn returns the OS-stored password for the "Slack Safe Storage"
// keychain entry. Replaced in tests via the test seam below.
//
// On macOS this triggers the system Keychain prompt. On Linux it reads
// libsecret via D-Bus. On unsupported platforms it returns ErrUnsupportedOS.
var keychainPasswordFn = systemKeychainPassword

// GetCookies returns every Slack authentication cookie known to the desktop
// app's cookies database — the `d` cookie always, and `d-s` when present.
func GetCookies() ([]Cookie, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, ErrUnsupportedOS
	}
	path, err := slackCookiesPath()
	if err != nil {
		return nil, err
	}
	return readCookiesFrom(path)
}

func readCookiesFrom(path string) ([]Cookie, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&immutable=1", url.PathEscape(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open cookies db: %w", err)
	}
	defer db.Close()

	metaVersion, err := readCookiesMetaVersion(db)
	if err != nil {
		return nil, err
	}

	rows, err := db.Query(
		`SELECT host_key, name, encrypted_value
		   FROM cookies
		  WHERE host_key LIKE '%slack.com'
		    AND name IN ('d','d-s')`,
	)
	if err != nil {
		return nil, fmt.Errorf("query cookies: %w", err)
	}
	defer rows.Close()

	type row struct {
		host string
		name string
		enc  []byte
	}
	var raw []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.host, &r.name, &r.enc); err != nil {
			return nil, fmt.Errorf("scan cookies: %w", err)
		}
		raw = append(raw, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, ErrCookieNotFound
	}

	keyV10, keyV11, err := platformCookieKeys()
	if err != nil {
		return nil, err
	}

	out := make([]Cookie, 0, len(raw))
	var lastErr error
	for _, r := range raw {
		val, err := decryptCookieValue(r.enc, keyV10, keyV11, metaVersion)
		if err != nil {
			lastErr = fmt.Errorf("decrypt %s: %w", r.name, err)
			continue
		}
		out = append(out, Cookie{Name: r.name, Value: val})
	}
	if len(out) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, ErrCookieNotFound
	}
	return out, nil
}

func readCookiesMetaVersion(db *sql.DB) (int, error) {
	var v string
	err := db.QueryRow(`SELECT value FROM meta WHERE key='version'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		// `meta` may not exist on very old DBs; treat as version 0.
		return 0, nil
	}
	n, _ := strconv.Atoi(v)
	return n, nil
}

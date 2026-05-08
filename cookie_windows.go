// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

//go:build windows

package slacktokens

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// slackLocalStatePath returns the path to Slack's Chromium "Local State"
// JSON file, used to obtain the DPAPI-wrapped cookie master key on Windows.
func slackLocalStatePath() (string, error) {
	root, err := slackProfileDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "Local State"), nil
}

// dpapiUnprotectFn is the test seam for DPAPI decryption. The default
// implementation calls the Win32 CryptUnprotectData API via x/sys/windows;
// tests can swap it for a deterministic stub.
var dpapiUnprotectFn = dpapiUnprotect

// systemKeychainPassword is unused on Windows but required for symmetry
// across platform files. The cookie key path goes via Local State + DPAPI,
// not via a per-app password.
func systemKeychainPassword() (string, error) {
	return "", errors.New("slacktokens: keychain password is not used on Windows")
}

// newPlatformDecrypter wires up the Windows cookie decrypt strategy:
//
//  1. Read %APPDATA%\Slack\Local State JSON.
//  2. base64-decode os_crypt.encrypted_key.
//  3. Strip the 5-byte "DPAPI" prefix.
//  4. CryptUnprotectData -> 32-byte AES-256 key.
//  5. AES-256-GCM decrypt: prefix(3) + IV(12) + ciphertext + tag(16).
//  6. If meta.version >= 24, strip the 32-byte SHA-256(host_key) prefix.
//
// v20 (Chrome 127+ app-bound encryption) is NOT used by Slack 4.50 because
// Electron does not ship the IElevator service that Chromium relies on. If a
// v20 row is encountered, we surface a clear error rather than silently fail.
func newPlatformDecrypter() (cookieDecrypter, error) {
	statePath, err := slackLocalStatePath()
	if err != nil {
		return nil, err
	}
	key, err := readLocalStateMasterKey(statePath)
	if err != nil {
		return nil, fmt.Errorf("read Slack Local State: %w", err)
	}
	return func(enc []byte, hostKey string, metaVersion int) (string, error) {
		return decryptCookieValueGCM(enc, key, hostKey, metaVersion)
	}, nil
}

// readLocalStateMasterKey returns the AES-256 master key recovered from
// Slack's Local State file. The expected JSON shape is:
//
//	{"os_crypt": {"encrypted_key": "<base64>"}}
//
// The decoded value begins with the literal ASCII bytes "DPAPI" followed by
// a CryptProtectData blob; the blob unprotects to a 32-byte key.
func readLocalStateMasterKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse Local State JSON: %w", err)
	}
	if parsed.OSCrypt.EncryptedKey == "" {
		return nil, errors.New("os_crypt.encrypted_key not present in Local State")
	}
	wrapped, err := base64.StdEncoding.DecodeString(parsed.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("base64-decode encrypted_key: %w", err)
	}
	if len(wrapped) < 5 || string(wrapped[:5]) != "DPAPI" {
		return nil, fmt.Errorf("encrypted_key missing DPAPI prefix (got %q)", firstBytesQuoted(wrapped, 5))
	}
	key, err := dpapiUnprotectFn(wrapped[5:])
	if err != nil {
		return nil, fmt.Errorf("DPAPI unprotect: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("expected 32-byte AES-256 key, got %d", len(key))
	}
	return key, nil
}

func firstBytesQuoted(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	return string(b[:n])
}

// decryptCookieValueGCM decrypts a Chromium v10/v11 cookie blob produced by
// Windows OSCrypt. The layout is:
//
//	[3]byte("v10"|"v11") | [12]byte(IV) | ciphertext | [16]byte(GCM tag)
//
// The Go AEAD interface treats `ciphertext || tag` as a single argument.
func decryptCookieValueGCM(enc, key []byte, hostKey string, metaVersion int) (string, error) {
	if len(enc) < 3 {
		return "", errors.New("encrypted value too short")
	}
	prefix := string(enc[:3])
	switch prefix {
	case "v10", "v11":
	case "v20":
		return "", errors.New("v20 (app-bound) cookie encountered; Slack/Electron should not produce this — please file an issue")
	default:
		return "", fmt.Errorf("unknown cookie encryption prefix %q", prefix)
	}
	const ivLen = 12
	const tagLen = 16
	if len(enc) < 3+ivLen+tagLen {
		return "", errors.New("ciphertext too short for GCM")
	}
	iv := enc[3 : 3+ivLen]
	body := enc[3+ivLen:]
	if len(key) != 32 {
		return "", fmt.Errorf("invalid AES-256 key length %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := aead.Open(nil, iv, body, nil)
	if err != nil {
		return "", fmt.Errorf("GCM open: %w", err)
	}
	if metaVersion >= 24 {
		// Plaintext is SHA-256(host_key) || cookie_value. Verify the prefix
		// matches before stripping; a mismatch means the row is from a
		// different host or an unexpected format and we shouldn't silently
		// chop off legitimate value bytes.
		sum := sha256.Sum256([]byte(hostKey))
		if len(plain) >= len(sum) && string(plain[:len(sum)]) == string(sum[:]) {
			plain = plain[len(sum):]
		}
	}
	return string(plain), nil
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

//go:build darwin

package slacktokens

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// macOS Keychain account names used by Chromium-based apps. Slack writes one
// of these depending on whether it was installed from the App Store or
// downloaded directly from slack.com.
var macKeychainAccounts = []string{"Slack Key", "Slack App Store Key"}

const macKeychainService = "Slack Safe Storage"

// systemKeychainPassword shells out to /usr/bin/security to read the Slack
// Safe Storage entry. This triggers the standard macOS authorization prompt
// (matching pycookiecheat's UX). No CGO required.
func systemKeychainPassword() (string, error) {
	var lastErr error
	for _, account := range macKeychainAccounts {
		out, err := exec.Command(
			"/usr/bin/security",
			"find-generic-password",
			"-w",
			"-s", macKeychainService,
			"-a", account,
		).Output()
		if err == nil {
			pw := strings.TrimRight(string(out), "\n")
			if pw != "" {
				return pw, nil
			}
		} else {
			lastErr = err
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("read Slack Safe Storage from macOS Keychain: %w", lastErr)
	}
	return "", errors.New("slack Safe Storage not found in Keychain (Slack may not be installed)")
}

// newPlatformDecrypter wires up the macOS cookie decrypt strategy:
// Keychain password -> PBKDF2(1003 iters) -> AES-128-CBC.
// Chromium on macOS only uses the v10 prefix, so keyV11 is left nil.
func newPlatformDecrypter() (cookieDecrypter, error) {
	pw, err := keychainPasswordFn()
	if err != nil {
		return nil, err
	}
	keyV10 := deriveKey([]byte(pw), 1003)
	return func(enc []byte, _ string, metaVersion int) (string, error) {
		return decryptCookieValueCBC(enc, keyV10, nil, metaVersion)
	}, nil
}

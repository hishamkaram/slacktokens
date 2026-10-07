// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

package slacktokens

import (
	"errors"
	"path/filepath"
)

// Workspace describes one Slack workspace as recorded in the desktop app's
// localConfig_v2 entry.
type Workspace struct {
	Token string `json:"token"`
	Name  string `json:"name"`
}

// Cookie is a name/value pair for a Slack authentication cookie.
type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	// Host is the cookie's host_key (e.g. ".slack.com" or ".slack-gov.com"),
	// used to pick the cookie matching a given workspace when more than one
	// Slack account (e.g. commercial + GovSlack) is signed in.
	Host string `json:"host,omitempty"`
}

// Result is the combined output of GetTokensAndCookie.
//
// Cookie holds the `d` cookie alone, mirroring the Python source library's
// shape. Cookies holds every Slack auth cookie found (`d`, and `d-s` when
// present) and is the field new callers should prefer.
type Result struct {
	Tokens  map[string]Workspace `json:"tokens"`
	Cookie  Cookie               `json:"cookie"`
	Cookies []Cookie             `json:"cookies"`
}

// Sentinel errors returned by package functions; check with errors.Is.
var (
	// ErrUnsupportedOS is returned on platforms other than macOS, Linux, and Windows.
	ErrUnsupportedOS = errors.New("slacktokens: only macOS, Linux, and Windows are supported")
	// ErrLocalConfigMissing is returned when no localConfig_v2 entry exists.
	ErrLocalConfigMissing = errors.New("slacktokens: localConfig_v2 not found")
	// ErrLocalConfigParse is returned when localConfig_v2 cannot be parsed.
	ErrLocalConfigParse = errors.New("slacktokens: localConfig_v2 not in expected format")
	// ErrCookieNotFound is returned when the d cookie row is missing.
	ErrCookieNotFound = errors.New("slacktokens: d cookie not found in Slack cookies database")
	// ErrProfileNotFound is returned when no Slack profile directory can be
	// located (e.g. none of the native/Snap/Flatpak locations exist on Linux).
	ErrProfileNotFound = errors.New("slacktokens: no Slack profile directory found")
)

// GetTokensAndCookie returns the Slack workspace tokens and authentication
// cookie(s). Works whether Slack is running or quit.
//
// The profile directory is resolved once and reused for both the tokens and the
// cookies read, so a concurrent Snap "current" rotation (or multiple installs)
// can never mix tokens from one profile with cookies from another.
func GetTokensAndCookie() (Result, error) {
	root, err := openProfileRoot(materializeOpts{levelDB: true, cookies: true})
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = root.Close() }()

	tmp, cleanup, err := materialize(root, materializeOpts{levelDB: true, cookies: true})
	if err != nil {
		return Result{}, err
	}
	defer cleanup()

	tokens, err := openAndExtractTokens(filepath.Join(tmp, "Local Storage", "leveldb"))
	if err != nil {
		return Result{}, err
	}
	cookies, err := readCookiesFrom(filepath.Join(tmp, "Cookies"), root)
	if err != nil {
		return Result{}, err
	}
	r := Result{Tokens: tokens, Cookies: cookies}
	for _, c := range cookies {
		if c.Name == "d" {
			r.Cookie = c
			break
		}
	}
	return r, nil
}

// GetCookie returns the Slack `d` authentication cookie. Parity with the
// Python source library.
func GetCookie() (Cookie, error) {
	cookies, err := GetCookies()
	if err != nil {
		return Cookie{}, err
	}
	for _, c := range cookies {
		if c.Name == "d" {
			return c, nil
		}
	}
	return Cookie{}, ErrCookieNotFound
}

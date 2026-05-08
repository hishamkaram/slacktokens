// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

package slacktokens

import "errors"

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
	// ErrUnsupportedOS is returned on platforms other than macOS and Linux.
	ErrUnsupportedOS = errors.New("slacktokens: only macOS and Linux are supported")
	// ErrLocalStorageLocked is returned when LevelDB is held by a running Slack.
	ErrLocalStorageLocked = errors.New("slacktokens: Local Storage is locked — have you quit Slack?")
	// ErrLocalConfigMissing is returned when no localConfig_v2 entry exists.
	ErrLocalConfigMissing = errors.New("slacktokens: localConfig_v2 not found")
	// ErrLocalConfigParse is returned when localConfig_v2 cannot be parsed.
	ErrLocalConfigParse = errors.New("slacktokens: localConfig_v2 not in expected format")
	// ErrCookieNotFound is returned when the d cookie row is missing.
	ErrCookieNotFound = errors.New("slacktokens: d cookie not found in Slack cookies database")
)

// GetTokensAndCookie returns the Slack workspace tokens and authentication
// cookie(s). Works whether Slack is running or quit.
func GetTokensAndCookie() (Result, error) {
	tokens, err := GetTokens()
	if err != nil {
		return Result{}, err
	}
	cookies, err := GetCookies()
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

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

// Package slacktokens extracts personal Slack workspace tokens and the
// authentication cookies (`d`, `d-s`) from the Slack desktop application's
// local storage.
//
// It is a Go port of github.com/hraftery/slacktokens (Python, GPLv3) and is
// itself distributed under GPLv3.
//
// Supported platforms: macOS, Linux, and Windows.
//
// These functions work whether Slack is running or quit. The profile directory
// is opened through a pinned os.Root (symlink-safe, escape-proof) and its
// LevelDB store and Cookies database are copied into a private 0700 temp
// directory, which the backends then open — so a running Slack's lock never
// blocks the read and a swapped symlink cannot redirect it.
//
// Example:
//
//	res, err := slacktokens.GetTokensAndCookie()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for url, ws := range res.Tokens {
//	    fmt.Printf("%s -> %s\n", url, ws.Token)
//	}
package slacktokens

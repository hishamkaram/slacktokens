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
// These functions work whether Slack is running or quit. If the LevelDB store
// is locked by a running Slack, it is snapshot-copied to a temp directory and
// read from the copy.
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

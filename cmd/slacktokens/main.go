// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

// Command slacktokens prints the Slack workspace tokens and authentication
// cookies extracted from the desktop app's local storage as JSON.
//
//	slacktokens                # full Result: {"tokens":..., "cookie":..., "cookies":...}
//	slacktokens -tokens        # only the tokens map
//	slacktokens -cookie        # only the d cookie
//	slacktokens -cookies       # all auth cookies (d, d-s)
//	slacktokens -out creds.json # write the full Result to a new 0600 file
//
// The -out form is the human-run replacement for the MCP server's dropped
// write_credentials_file tool: the MCP server never hands credentials to the AI,
// so a person who wants them in a file runs this themselves.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hishamkaram/slacktokens"
)

func main() {
	var (
		tokensOnly  = flag.Bool("tokens", false, "print only the tokens map")
		cookieOnly  = flag.Bool("cookie", false, "print only the d cookie")
		cookiesOnly = flag.Bool("cookies", false, "print all auth cookies (d, d-s)")
		outFile     = flag.String("out", "", "write the full credential Result as JSON to this new file (mode 0600; refuses to overwrite)")
	)
	flag.Parse()

	if *outFile != "" {
		exitOn(writeOut(*outFile))
		return
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	switch {
	case *tokensOnly:
		t, err := slacktokens.GetTokens()
		exitOn(err)
		exitOn(enc.Encode(t))
	case *cookieOnly:
		c, err := slacktokens.GetCookie()
		exitOn(err)
		exitOn(enc.Encode(c))
	case *cookiesOnly:
		c, err := slacktokens.GetCookies()
		exitOn(err)
		exitOn(enc.Encode(c))
	default:
		r, err := slacktokens.GetTokensAndCookie()
		exitOn(err)
		exitOn(enc.Encode(r))
	}
}

// writeOut extracts the full credential Result and writes it as indented JSON to
// a NEWLY created file at path, mode 0600. It refuses to overwrite an existing
// file (O_EXCL) so a stray path can't clobber unrelated data, and reports the
// path on success.
func writeOut(path string) error {
	r, err := slacktokens.GetTokensAndCookie()
	if err != nil {
		return err
	}
	if err := writeResultFile(path, r); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "slacktokens: wrote %d workspace(s) and %d cookie(s) to %s (mode 0600)\n",
		len(r.Tokens), len(r.Cookies), path)
	return nil
}

// writeResultFile marshals r as indented JSON to path at mode 0600, refusing to
// overwrite an existing file. The write is atomic and leaves no partial file: the
// JSON is written to a sibling temp file (O_EXCL, 0600), fsync'd and closed, then
// hard-linked into place with os.Link; on any failure the temp file is removed.
// os.Link within the same directory is atomic and fails if the target already
// exists, so there is no overwrite race, a reader never sees a half-written file,
// and a disk-full error never strands credential bytes at the target path.
//
// NOTE: 0600 restricts access by Unix permission bits only. On Windows the mode
// is not equivalent to an ACL; choose an output path under your own user profile.
func writeResultFile(path string, r slacktokens.Result) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".slacktokens-out-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we return before the temp is linked into place.
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}

	// Link is atomic and fails if the target already exists — a true
	// no-clobber guarantee with no TOCTOU window (unlike stat-then-rename), and
	// the temp holds the complete file so the target never appears half-written.
	if err := os.Link(tmpName, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite existing file %s", path)
		}
		return fmt.Errorf("finalize %s: %w", path, err)
	}
	committed = true // tmp now linked as path; remove the temp name below.
	_ = os.Remove(tmpName)
	return nil
}

func exitOn(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "slacktokens:", err)
	os.Exit(1)
}

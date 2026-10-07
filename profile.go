// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package slacktokens

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// profileDirEnv overrides Slack's profile directory. Trusted/test-only: when set
// it is opened directly as a root, bypassing discovery and validation.
const profileDirEnv = "SLACKTOKENS_PROFILE_DIR"

// profileAdvisory emits a non-fatal discovery notice (e.g. multiple installs
// found). It is a package var so tests can capture it; by default it writes one
// line to stderr, keeping stdout clean for the MCP stdio protocol.
var profileAdvisory = func(msg string) {
	fmt.Fprintln(os.Stderr, msg)
}

// profileCandidate is one possible Slack profile location: a stable anchor
// directory and the profile path relative to it. The anchor is opened as an
// os.Root; the profile is then opened relative to that anchor, so a stray
// symlink (e.g. Snap's "current") can never redirect reads outside the anchor.
type profileCandidate struct {
	label  string
	anchor string
	rel    string
}

// profileCandidates lists Slack's possible profile locations for the current OS,
// in preference order. No snap/flatpak binaries are consulted — locations are
// derived from HOME and the environment.
func profileCandidates(home string) ([]profileCandidate, error) {
	switch runtime.GOOS {
	case "linux":
		cfg, err := os.UserConfigDir()
		if err != nil || cfg == "" {
			cfg = filepath.Join(home, ".config")
		}
		return []profileCandidate{
			{"native", cfg, "Slack"},
			{"snap", filepath.Join(home, "snap", "slack"), filepath.Join("current", ".config", "Slack")},
			{"flatpak", filepath.Join(home, ".var", "app", "com.slack.Slack"), filepath.Join("config", "Slack")},
		}, nil
	case "darwin":
		return []profileCandidate{
			{"direct", filepath.Join(home, "Library", "Application Support"), "Slack"},
			{"appstore", filepath.Join(home, "Library", "Containers",
				"com.tinyspeck.slackmacgap", "Data", "Library", "Application Support"), "Slack"},
		}, nil
	case "windows":
		base := os.Getenv("APPDATA")
		if base == "" {
			base = filepath.Join(home, "AppData", "Roaming")
		}
		return []profileCandidate{{"appdata", base, "Slack"}}, nil
	default:
		return nil, ErrUnsupportedOS
	}
}

// openProfileRoot discovers Slack's profile directory and returns an *os.Root
// pinned to it. Every credential read goes through this root, so symlink escapes
// are refused by the kernel and the directory fd is stable for the operation.
// Honors $SLACKTOKENS_PROFILE_DIR (trusted/test-only: opened directly). opts
// says which stores the caller will read, so a profile is validated only for
// what is actually needed (e.g. GetTokens does not reject a profile that happens
// to lack a Cookies database). The caller must Close the returned root.
func openProfileRoot(opts materializeOpts) (*os.Root, error) {
	if p := os.Getenv(profileDirEnv); p != "" {
		r, err := os.OpenRoot(p)
		if err != nil {
			return nil, fmt.Errorf("%w: open %s=%q: %w", ErrProfileNotFound, profileDirEnv, p, err)
		}
		return r, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	candidates, err := profileCandidates(home)
	if err != nil {
		return nil, err
	}

	type opened struct {
		root  *os.Root
		label string
	}
	var valid []opened
	var reasons []string
	for _, c := range candidates {
		root, reason := openCandidate(c, opts)
		if root != nil {
			valid = append(valid, opened{root, c.label})
			continue
		}
		reasons = append(reasons, fmt.Sprintf("  [%s] %s — %s", c.label, filepath.Join(c.anchor, c.rel), reason))
	}

	if len(valid) == 0 {
		return nil, fmt.Errorf("%w; checked:\n%s\nset %s to select a profile explicitly",
			ErrProfileNotFound, strings.Join(reasons, "\n"), profileDirEnv)
	}
	// Auto-pick the highest-preference valid profile; close the rest.
	for i := 1; i < len(valid); i++ {
		_ = valid[i].root.Close()
	}
	if len(valid) > 1 {
		profileAdvisory(fmt.Sprintf(
			"slacktokens: multiple Slack profiles found; using [%s] %s (set %s to override)",
			valid[0].label, valid[0].root.Name(), profileDirEnv))
	}
	return valid[0].root, nil
}

// openCandidate opens the anchor as a root, opens the profile relative to it, and
// validates it. On failure it returns a short human-readable reason.
func openCandidate(c profileCandidate, opts materializeOpts) (*os.Root, string) {
	anchor, err := os.OpenRoot(c.anchor)
	if err != nil {
		return nil, "install location not present"
	}
	defer func() { _ = anchor.Close() }()

	profile, err := anchor.OpenRoot(c.rel)
	if err != nil {
		return nil, "does not exist"
	}
	if reason, ok := validateProfileRoot(profile, opts); !ok {
		_ = profile.Close()
		return nil, reason
	}
	return profile, ""
}

// validateProfileRoot confirms a root looks like a real, logged-in Slack profile
// for the stores the caller needs: a Local Storage/leveldb directory when tokens
// are wanted, and a Cookies database file when cookies are wanted. Validating only
// what will be read means a token-only read is not rejected by a missing Cookies
// DB (and vice versa). All lookups go through the root, so escaping symlinks are
// refused. When opts requests neither store, LevelDB is required as the baseline
// marker of a Slack profile.
func validateProfileRoot(r *os.Root, opts materializeOpts) (string, bool) {
	if opts.levelDB || (!opts.levelDB && !opts.cookies) {
		if fi, err := r.Stat(filepath.Join("Local Storage", "leveldb")); err != nil || !fi.IsDir() {
			return "missing Local Storage/leveldb", false
		}
	}
	if opts.cookies {
		hasCookies := false
		for _, name := range []string{filepath.Join("Network", "Cookies"), "Cookies"} {
			if fi, err := r.Stat(name); err == nil && fi.Mode().IsRegular() {
				hasCookies = true
				break
			}
		}
		if !hasCookies {
			return "missing Cookies database", false
		}
	}
	return "", true
}

// materializeOpts selects which stores to copy. Copying only what a reader needs
// means a transient problem in one store (e.g. a Cookies sidecar race) never
// fails an unrelated read (e.g. GetTokens).
type materializeOpts struct {
	levelDB bool
	cookies bool
}

// materialize copies the requested stores from the profile root into a private
// 0700 temp directory and returns its path. Reading through the root is
// symlink-safe; the backends then open our own copies by path. The caller must
// call cleanup.
func materialize(root *os.Root, opts materializeOpts) (dir string, cleanup func(), err error) {
	tmp, err := os.MkdirTemp("", "slacktokens-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() {
		if rmErr := os.RemoveAll(tmp); rmErr != nil {
			// Surface it: a leftover temp dir may hold copied credential bytes.
			fmt.Fprintf(os.Stderr, "slacktokens: warning: could not remove temp dir %s: %v\n", tmp, rmErr)
		}
	}

	if opts.cookies {
		if err := copyCookies(root, tmp); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	if opts.levelDB {
		if err := copyLevelDB(root, tmp); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	return tmp, cleanup, nil
}

// copyCookies copies the Cookies database and its SQLite sidecars (-wal, -shm,
// -journal) into tmp as "Cookies*". Sidecars are optional. The destination name
// is always "Cookies" so SQLite's sidecar lookup matches.
func copyCookies(root *os.Root, tmp string) error {
	dir, file := "Network", "Cookies"
	if _, err := root.Stat(filepath.Join(dir, file)); err != nil {
		dir = "." // legacy top-level Cookies
	}
	if err := copyThroughRoot(root, filepath.Join(dir, file), filepath.Join(tmp, "Cookies")); err != nil {
		return fmt.Errorf("copy cookies: %w", err)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		src := filepath.Join(dir, file+suffix)
		if _, err := root.Stat(src); err != nil {
			continue // sidecar absent — fine
		}
		if err := copyThroughRoot(root, src, filepath.Join(tmp, "Cookies"+suffix)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // sidecar vanished between Stat and copy (e.g. a checkpoint) — fine
			}
			return fmt.Errorf("copy %s: %w", file+suffix, err)
		}
	}
	return nil
}

// levelDBCopyAttempts bounds retries when the live store mutates mid-copy.
const levelDBCopyAttempts = 3

// copyLevelDB copies the LevelDB directory into tmp/"Local Storage/leveldb". Data
// files are copied first and CURRENT last; CURRENT is re-read afterward and, if
// it changed (a compaction raced the copy), the copy is retried a bounded number
// of times before failing. LevelDB's own recovery tolerates torn log tails.
func copyLevelDB(root *os.Root, tmp string) error {
	rel := filepath.Join("Local Storage", "leveldb")
	dst := filepath.Join(tmp, rel)
	var lastErr error
	for attempt := 0; attempt < levelDBCopyAttempts; attempt++ {
		if err := os.MkdirAll(dst, 0o700); err != nil {
			return err
		}
		changed, err := copyLevelDBOnce(root, rel, dst)
		if err == nil && !changed {
			return nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New("CURRENT changed during copy")
		}
		_ = os.RemoveAll(dst)
	}
	return fmt.Errorf("leveldb snapshot unstable after %d attempts: %w", levelDBCopyAttempts, lastErr)
}

func copyLevelDBOnce(root *os.Root, rel, dst string) (changed bool, err error) {
	// Read CURRENT FIRST: it names the live MANIFEST, so we learn the manifest we
	// must guarantee in the copy before listing the directory. A CURRENT read
	// error is fatal (not ignored) — without it the copy is meaningless.
	curBefore, err := root.ReadFile(filepath.Join(rel, "CURRENT"))
	if err != nil {
		return false, fmt.Errorf("read CURRENT: %w", err)
	}
	manifest := strings.TrimSpace(string(curBefore))

	// Snapshot the manifest bytes BEFORE listing the directory. The manifest
	// references a fixed set of tables; because we read it first, every table it
	// names already existed and will appear in the ReadDir below. Any table added
	// afterward is reflected only by a change to the live manifest (an in-place
	// append or a switch to a new manifest), which the post-copy re-read detects —
	// closing the "SSTable created after ReadDir, referenced by an appended
	// manifest" race that a CURRENT-only check misses.
	var manBytes []byte
	if manifest != "" {
		manBytes, err = root.ReadFile(filepath.Join(rel, manifest))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return true, nil // compacted away already; retry
			}
			return false, fmt.Errorf("read manifest %s: %w", manifest, err)
		}
	}

	d, err := root.Open(rel)
	if err != nil {
		return false, err
	}
	entries, err := d.ReadDir(-1)
	_ = d.Close()
	if err != nil {
		return false, err
	}

	for _, e := range entries {
		name := e.Name()
		// Skip LOCK, CURRENT and the manifest (written from our snapshot below).
		if e.IsDir() || name == "LOCK" || name == "CURRENT" || name == manifest {
			continue
		}
		if err := copyThroughRoot(root, filepath.Join(rel, name), filepath.Join(dst, name)); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // compacted away between ReadDir and copy
			}
			return false, err
		}
	}

	// Persist the manifest from our snapshot (not a fresh copy), so the copied
	// manifest matches the table set we captured, then write CURRENT last.
	if manifest != "" {
		// #nosec G703 G304 -- dst is our own 0700 MkdirTemp directory, not caller input.
		if err := os.WriteFile(filepath.Join(dst, manifest), manBytes, 0o600); err != nil {
			return false, err
		}
	}
	// #nosec G703 G304 -- dst is our own 0700 MkdirTemp directory, not caller input.
	if err := os.WriteFile(filepath.Join(dst, "CURRENT"), curBefore, 0o600); err != nil {
		return false, err
	}

	// Re-read CURRENT and the manifest: if either changed during the copy, the
	// store moved on and our snapshot may be inconsistent → retry.
	curAfter, err := root.ReadFile(filepath.Join(rel, "CURRENT"))
	if err != nil {
		return false, fmt.Errorf("re-read CURRENT: %w", err)
	}
	if !bytes.Equal(curBefore, curAfter) {
		return true, nil
	}
	if manifest != "" {
		manAfter, err := root.ReadFile(filepath.Join(rel, manifest))
		if err != nil {
			return true, nil // manifest changed/removed under us; retry
		}
		if !bytes.Equal(manBytes, manAfter) {
			return true, nil
		}
	}
	return false, nil
}

// copyThroughRoot copies a file read through root (symlink-safe, confined) to a
// freshly created 0600 file at dstPath.
func copyThroughRoot(root *os.Root, relSrc, dstPath string) error {
	in, err := root.Open(relSrc)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	// #nosec G304 G703 -- dstPath is always under our own 0700 MkdirTemp directory.
	out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

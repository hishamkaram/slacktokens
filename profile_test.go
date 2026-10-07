// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package slacktokens

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// stageProfile creates the structure validateProfileRoot requires (a
// Local Storage/leveldb directory and a Cookies file) plus a "WHICH" marker file
// naming the install, so a test can read it back through the selected root and
// prove which candidate was picked.
func stageProfile(t *testing.T, dir, label string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "Local Storage", "leveldb"), 0o755); err != nil {
		t.Fatalf("stage leveldb: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Cookies"), []byte("stub"), 0o600); err != nil {
		t.Fatalf("stage cookies: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "WHICH"), []byte(label), 0o600); err != nil {
		t.Fatalf("stage marker: %v", err)
	}
}

func setLinuxEnv(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv(profileDirEnv, "")
}

func captureAdvisory(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := profileAdvisory
	profileAdvisory = func(msg string) { got = append(got, msg) }
	t.Cleanup(func() { profileAdvisory = prev })
	return &got
}

func requireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("linux-only discovery test (GOOS=%s)", runtime.GOOS)
	}
}

// pickedLabel opens the discovered profile and reads the WHICH marker.
func pickedLabel(t *testing.T) string {
	t.Helper()
	root, err := openProfileRoot(materializeOpts{levelDB: true, cookies: true})
	if err != nil {
		t.Fatalf("openProfileRoot: %v", err)
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile("WHICH")
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	return string(b)
}

func TestOpenProfileRoot_NativeOnly(t *testing.T) {
	requireLinux(t)
	home := t.TempDir()
	setLinuxEnv(t, home)
	stageProfile(t, filepath.Join(home, ".config", "Slack"), "native")
	if got := pickedLabel(t); got != "native" {
		t.Fatalf("got %q, want native", got)
	}
}

func TestOpenProfileRoot_SnapOnly_FollowsCurrentSymlink(t *testing.T) {
	requireLinux(t)
	home := t.TempDir()
	setLinuxEnv(t, home)
	stageProfile(t, filepath.Join(home, "snap", "slack", "262", ".config", "Slack"), "snap")
	if err := os.Symlink("262", filepath.Join(home, "snap", "slack", "current")); err != nil {
		t.Fatalf("symlink current: %v", err)
	}
	if got := pickedLabel(t); got != "snap" {
		t.Fatalf("got %q, want snap", got)
	}
}

func TestOpenProfileRoot_FlatpakOnly(t *testing.T) {
	requireLinux(t)
	home := t.TempDir()
	setLinuxEnv(t, home)
	stageProfile(t, filepath.Join(home, ".var", "app", "com.slack.Slack", "config", "Slack"), "flatpak")
	if got := pickedLabel(t); got != "flatpak" {
		t.Fatalf("got %q, want flatpak", got)
	}
}

func TestOpenProfileRoot_HonorsXDGConfigHome(t *testing.T) {
	requireLinux(t)
	home := t.TempDir()
	setLinuxEnv(t, home)
	xdg := filepath.Join(home, "customconfig")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	stageProfile(t, filepath.Join(xdg, "Slack"), "xdg-native")
	if got := pickedLabel(t); got != "xdg-native" {
		t.Fatalf("got %q, want xdg-native", got)
	}
}

func TestOpenProfileRoot_XDGOutsideHome(t *testing.T) {
	requireLinux(t)
	home := t.TempDir()
	setLinuxEnv(t, home)
	xdg := t.TempDir() // outside HOME
	t.Setenv("XDG_CONFIG_HOME", xdg)
	stageProfile(t, filepath.Join(xdg, "Slack"), "xdg-out")
	if got := pickedLabel(t); got != "xdg-out" {
		t.Fatalf("got %q, want xdg-out", got)
	}
}

func TestOpenProfileRoot_MultipleValid_PrefersNativeAndWarns(t *testing.T) {
	requireLinux(t)
	home := t.TempDir()
	setLinuxEnv(t, home)
	adv := captureAdvisory(t)
	stageProfile(t, filepath.Join(home, ".config", "Slack"), "native")
	stageProfile(t, filepath.Join(home, "snap", "slack", "262", ".config", "Slack"), "snap")
	if err := os.Symlink("262", filepath.Join(home, "snap", "slack", "current")); err != nil {
		t.Fatalf("symlink current: %v", err)
	}
	if got := pickedLabel(t); got != "native" {
		t.Fatalf("multiple installs should prefer native, got %q", got)
	}
	if len(*adv) != 1 {
		t.Fatalf("want 1 advisory, got %d: %v", len(*adv), *adv)
	}
	if !strings.Contains((*adv)[0], "native") || !strings.Contains((*adv)[0], profileDirEnv) {
		t.Errorf("advisory should name chosen install + override env; got %q", (*adv)[0])
	}
}

func TestOpenProfileRoot_SnapOverFlatpak(t *testing.T) {
	requireLinux(t)
	home := t.TempDir()
	setLinuxEnv(t, home)
	stageProfile(t, filepath.Join(home, "snap", "slack", "262", ".config", "Slack"), "snap")
	if err := os.Symlink("262", filepath.Join(home, "snap", "slack", "current")); err != nil {
		t.Fatalf("symlink current: %v", err)
	}
	stageProfile(t, filepath.Join(home, ".var", "app", "com.slack.Slack", "config", "Slack"), "flatpak")
	if got := pickedLabel(t); got != "snap" {
		t.Fatalf("snap should win over flatpak, got %q", got)
	}
}

func TestOpenProfileRoot_NoneValid_ErrorListsCandidates(t *testing.T) {
	requireLinux(t)
	home := t.TempDir()
	setLinuxEnv(t, home)

	_, err := openProfileRoot(materializeOpts{levelDB: true, cookies: true})
	if !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("want ErrProfileNotFound, got %v", err)
	}
	msg := err.Error()
	for _, label := range []string{"[native]", "[snap]", "[flatpak]"} {
		if !strings.Contains(msg, label) {
			t.Errorf("error should tag %s; got:\n%s", label, msg)
		}
	}
	if !strings.Contains(msg, profileDirEnv) {
		t.Errorf("error should mention %s; got:\n%s", profileDirEnv, msg)
	}
}

func TestOpenProfileRoot_IncompleteProfile_Rejected(t *testing.T) {
	requireLinux(t)
	home := t.TempDir()
	setLinuxEnv(t, home)
	// leveldb present, no Cookies → not a usable profile.
	if err := os.MkdirAll(filepath.Join(home, ".config", "Slack", "Local Storage", "leveldb"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := openProfileRoot(materializeOpts{levelDB: true, cookies: true})
	if !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("want ErrProfileNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), "missing Cookies database") {
		t.Errorf("want cookies reason; got:\n%s", err)
	}
}

func TestOpenProfileRoot_SnapCurrentEscapingHome_Rejected(t *testing.T) {
	requireLinux(t)
	home := t.TempDir()
	setLinuxEnv(t, home)
	// A valid-looking profile OUTSIDE the snap anchor, reached via current.
	outside := t.TempDir()
	stageProfile(t, filepath.Join(outside, ".config", "Slack"), "evil")
	if err := os.MkdirAll(filepath.Join(home, "snap", "slack"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "snap", "slack", "current")); err != nil {
		t.Fatalf("symlink current: %v", err)
	}
	// Only the (escaping) snap candidate exists → os.Root refuses it → none valid.
	_, err := openProfileRoot(materializeOpts{levelDB: true, cookies: true})
	if !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("escaping snap current must be refused, got %v", err)
	}
}

// Discovery validates only the stores the caller needs: a token-only read must
// accept a profile that has LevelDB but no Cookies DB, while a cookie read of the
// same profile must be rejected.
func TestOpenProfileRoot_ValidatesOnlyNeededStores(t *testing.T) {
	requireLinux(t)
	home := t.TempDir()
	setLinuxEnv(t, home)
	// Native profile with LevelDB but deliberately NO Cookies database.
	if err := os.MkdirAll(filepath.Join(home, ".config", "Slack", "Local Storage", "leveldb"), 0o755); err != nil {
		t.Fatal(err)
	}

	root, err := openProfileRoot(materializeOpts{levelDB: true})
	if err != nil {
		t.Fatalf("token-only discovery should accept a cookie-less profile: %v", err)
	}
	_ = root.Close()

	if _, err := openProfileRoot(materializeOpts{cookies: true}); !errors.Is(err, ErrProfileNotFound) {
		t.Fatalf("cookie discovery should reject a profile with no Cookies DB, got %v", err)
	}
}

func TestOpenProfileRoot_OverrideShortCircuits(t *testing.T) {
	home := t.TempDir()
	setLinuxEnv(t, home)
	override := t.TempDir()
	// Mark it; override is used verbatim without the leveldb/cookies validation.
	if err := os.WriteFile(filepath.Join(override, "WHICH"), []byte("override"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(profileDirEnv, override)
	if got := pickedLabel(t); got != "override" {
		t.Fatalf("got %q, want override", got)
	}
}

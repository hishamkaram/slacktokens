package slacktokens

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

// profileDirEnv overrides Slack's profile directory. Used by tests.
const profileDirEnv = "SLACKTOKENS_PROFILE_DIR"

// slackProfileDir returns the path to Slack's user data directory, which
// contains both Local Storage (LevelDB) and the Cookies SQLite file.
//
// Honors $SLACKTOKENS_PROFILE_DIR for tests. On macOS, falls back to the
// Mac App Store container if the direct-download path doesn't exist.
func slackProfileDir() (string, error) {
	if p := os.Getenv(profileDirEnv); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch runtime.GOOS {
	case "darwin":
		direct := filepath.Join(home, "Library", "Application Support", "Slack")
		if _, err := os.Stat(direct); err == nil {
			return direct, nil
		}
		appstore := filepath.Join(home, "Library", "Containers", "com.tinyspeck.slackmacgap",
			"Data", "Library", "Application Support", "Slack")
		if _, err := os.Stat(appstore); err == nil {
			return appstore, nil
		}
		// Neither found — return direct path so the downstream error mentions
		// the more familiar location.
		return direct, nil
	case "linux":
		return filepath.Join(home, ".config", "Slack"), nil
	default:
		return "", ErrUnsupportedOS
	}
}

// slackLevelDBPath returns the path to Slack's LevelDB localStorage directory.
func slackLevelDBPath() (string, error) {
	root, err := slackProfileDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "Local Storage", "leveldb"), nil
}

// slackCookiesPath returns the path to Slack's Cookies SQLite file.
func slackCookiesPath() (string, error) {
	root, err := slackProfileDir()
	if err != nil {
		return "", err
	}
	// Newer Chromium puts Cookies under Network/Cookies. Older puts it at the
	// top level. Prefer Network/ if it exists.
	netPath := filepath.Join(root, "Network", "Cookies")
	if _, err := os.Stat(netPath); err == nil {
		return netPath, nil
	}
	topPath := filepath.Join(root, "Cookies")
	if _, err := os.Stat(topPath); err == nil {
		return topPath, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		// Return the more common location for the error message.
		return netPath, nil
	}
	return netPath, nil
}

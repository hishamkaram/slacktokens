package slacktokens

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const localConfigKey = "localConfig_v2"

// GetTokens returns a map keyed by Slack workspace URL containing the personal
// xoxc- token and the workspace's display name. Slack must be quit before
// calling, since LevelDB is single-writer and locked while Slack is running.
func GetTokens() (map[string]Workspace, error) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		return nil, ErrUnsupportedOS
	}
	path, err := slackLevelDBPath()
	if err != nil {
		return nil, err
	}
	return readTokensFrom(path)
}

func readTokensFrom(path string) (map[string]Workspace, error) {
	db, err := leveldb.OpenFile(path, &opt.Options{ReadOnly: true})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "lock") {
			return nil, fmt.Errorf("%w: %v", ErrLocalStorageLocked, err)
		}
		return nil, fmt.Errorf("open leveldb at %s: %w", path, err)
	}
	defer db.Close()

	iter := db.NewIterator(nil, nil)
	defer iter.Release()

	keyMatch := []byte(localConfigKey)
	var raw []byte
	for iter.Next() {
		if bytes.Contains(iter.Key(), keyMatch) {
			raw = append(raw[:0], iter.Value()...)
			break
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("iterate leveldb: %w", err)
	}
	if raw == nil {
		return nil, ErrLocalConfigMissing
	}

	cfg, err := parseLocalConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLocalConfigParse, err)
	}

	teamsAny, ok := cfg["teams"]
	if !ok {
		return nil, fmt.Errorf("%w: missing teams field", ErrLocalConfigParse)
	}
	teams, ok := teamsAny.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: teams field is not an object", ErrLocalConfigParse)
	}

	out := make(map[string]Workspace, len(teams))
	for _, v := range teams {
		t, ok := v.(map[string]any)
		if !ok {
			continue
		}
		url, _ := t["url"].(string)
		token, _ := t["token"].(string)
		name, _ := t["name"].(string)
		if url == "" || token == "" {
			continue
		}
		out[url] = Workspace{Token: token, Name: name}
	}
	if len(out) == 0 {
		return nil, errors.New("slacktokens: localConfig_v2 has no teams with token+url")
	}
	return out, nil
}

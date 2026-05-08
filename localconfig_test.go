package slacktokens

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf16"
)

func encodeUTF16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(u))
	for i, c := range u {
		out[2*i] = byte(c)
		out[2*i+1] = byte(c >> 8)
	}
	return out
}

func TestParseLocalConfig_UTF8(t *testing.T) {
	body := `{"teams":{"T1":{"url":"https://a.slack.com","token":"xoxc-1","name":"A"}}}`
	got, err := parseLocalConfig([]byte(body))
	if err != nil {
		t.Fatalf("parseLocalConfig: %v", err)
	}
	teams, ok := got["teams"].(map[string]any)
	if !ok {
		t.Fatalf("teams missing or wrong type: %#v", got["teams"])
	}
	if len(teams) != 1 {
		t.Fatalf("expected 1 team, got %d", len(teams))
	}
}

func TestParseLocalConfig_UTF8WithLatin1Prefix(t *testing.T) {
	// 0x01 prefix means Latin-1; ASCII content is identical bytes either way.
	body := []byte{0x01}
	body = append(body, []byte(`{"teams":{"T1":{"url":"https://a.slack.com","token":"xoxc-1","name":"A"}}}`)...)
	got, err := parseLocalConfig(body)
	if err != nil {
		t.Fatalf("parseLocalConfig: %v", err)
	}
	if _, ok := got["teams"]; !ok {
		t.Fatalf("teams missing: %#v", got)
	}
}

func TestParseLocalConfig_UTF16LE(t *testing.T) {
	body := []byte{0x00}
	body = append(body, encodeUTF16LE(`{"teams":{"T1":{"url":"https://a.slack.com","token":"xoxc-1","name":"A"}}}`)...)
	got, err := parseLocalConfig(body)
	if err != nil {
		t.Fatalf("parseLocalConfig: %v", err)
	}
	if _, ok := got["teams"]; !ok {
		t.Fatalf("teams missing: %#v", got)
	}
}

func TestParseLocalConfig_UTF16LE_NoPrefix(t *testing.T) {
	// No StorageFormat prefix; rely on NUL-density heuristic to pick UTF-16LE.
	body := encodeUTF16LE(`{"teams":{"T1":{"url":"https://a.slack.com","token":"xoxc-1","name":"A"}}}`)
	got, err := parseLocalConfig(body)
	if err != nil {
		t.Fatalf("parseLocalConfig: %v", err)
	}
	if _, ok := got["teams"]; !ok {
		t.Fatalf("teams missing: %#v", got)
	}
}

func TestParseLocalConfig_PaddedSnippet(t *testing.T) {
	// Garbage before/after a JSON object — exercise snippet extraction.
	body := []byte(`junkjunkjunk{"teams":{"T1":{"url":"https://a.slack.com","token":"xoxc-1","name":"A"}}}trailing`)
	got, err := parseLocalConfig(body)
	if err != nil {
		t.Fatalf("parseLocalConfig: %v", err)
	}
	if _, ok := got["teams"]; !ok {
		t.Fatalf("teams missing: %#v", got)
	}
}

func TestParseLocalConfig_RelaxedControlChars(t *testing.T) {
	// Raw \x09 (tab) inside a JSON string is rejected by encoding/json.
	// Relaxed pass should escape and succeed.
	raw := []byte("{\"teams\":{\"T1\":{\"url\":\"https://a.slack.com\",\"token\":\"xoxc\t1\",\"name\":\"A\"}}}")
	got, err := parseLocalConfig(raw)
	if err != nil {
		t.Fatalf("parseLocalConfig (relaxed): %v", err)
	}
	teams := got["teams"].(map[string]any)
	t1 := teams["T1"].(map[string]any)
	if !strings.Contains(t1["token"].(string), "xoxc") {
		t.Fatalf("token not preserved: %#v", t1["token"])
	}
}

func TestParseLocalConfig_Empty(t *testing.T) {
	if _, err := parseLocalConfig(nil); err == nil {
		t.Fatal("expected error for nil input")
	}
	if _, err := parseLocalConfig([]byte{}); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseLocalConfig_Garbage(t *testing.T) {
	if _, err := parseLocalConfig([]byte("\x01not json at all")); err == nil {
		t.Fatal("expected error for non-JSON input")
	}
}

func TestRelaxControlChars_OutsideStrings(t *testing.T) {
	// Control chars outside strings (between objects) shouldn't be touched —
	// only inside string literals.
	in := "{\n  \"a\": 1\n}"
	out := relaxControlChars(in)
	if out != in {
		t.Fatalf("relaxControlChars touched non-string content: %q -> %q", in, out)
	}
}

func TestRelaxControlChars_InsideStrings(t *testing.T) {
	in := "\"a\tb\""
	out := relaxControlChars(in)
	want := "\"a\\u0009b\""
	if out != want {
		t.Fatalf("relax: got %q want %q", out, want)
	}
	// And the relaxed result must parse.
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("relaxed result not valid JSON: %v", err)
	}
}

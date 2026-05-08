// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

package slacktokens

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// parseLocalConfig parses Chromium localStorage value bytes for the
// localConfig_v2 entry written by the Slack desktop app.
//
// Chromium prefixes localStorage values with a single StorageFormat byte:
//
//	0x00 -> UTF-16LE
//	0x01 -> Latin-1 (one byte per code point)
//
// See components/services/storage/dom_storage/local_storage_impl.cc and
// cached_storage_area.cc in current Chromium main. Older versions also wrote
// 0x02-prefixed values; we drop the prefix and fall back to encoding sniffing.
func parseLocalConfig(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return nil, errors.New("localConfig is empty")
	}

	var (
		data      []byte
		encodings []string
	)

	switch raw[0] {
	case 0x00:
		data = raw[1:]
		encodings = []string{"utf-16-le", "utf-8"}
	case 0x01:
		data = raw[1:]
		encodings = []string{"latin-1", "utf-8", "utf-16-le"}
	case 0x02:
		data = raw[1:]
		encodings = []string{"utf-8", "utf-16-le"}
	default:
		data = raw
		if bytes.Count(data, []byte{0}) > len(data)/4 {
			encodings = []string{"utf-16-le", "utf-8"}
		} else {
			encodings = []string{"utf-8", "utf-16-le", "latin-1"}
		}
	}

	var lastErr error
	for _, enc := range encodings {
		text, err := decodeText(data, enc)
		if err != nil {
			lastErr = err
			continue
		}

		v, perr := tryParse(text)
		if perr == nil {
			return v, nil
		}
		lastErr = perr

		if start := strings.IndexByte(text, '{'); start >= 0 {
			if end := strings.LastIndexByte(text, '}'); end > start {
				snippet := text[start : end+1]
				v, perr := tryParse(snippet)
				if perr == nil {
					return v, nil
				}
				lastErr = perr
			}
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("localConfig not parseable: %w", lastErr)
	}
	return nil, errors.New("localConfig not parseable")
}

// tryParse attempts strict JSON, then a relaxed pass that escapes raw
// control characters inside string literals (Python json.loads strict=False).
func tryParse(text string) (map[string]any, error) {
	var v map[string]any
	err := json.Unmarshal([]byte(text), &v)
	if err == nil {
		return v, nil
	}
	relaxed := relaxControlChars(text)
	if relaxed == text {
		return nil, err
	}
	if err2 := json.Unmarshal([]byte(relaxed), &v); err2 != nil {
		return nil, err2
	}
	return v, nil
}

// relaxControlChars escapes raw control characters (\x00..\x1F other than
// already-escaped) that appear inside JSON string literals. Outside strings
// the input is left alone.
func relaxControlChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inString := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			b.WriteByte(c)
			continue
		}
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		switch {
		case c == '\\':
			b.WriteByte(c)
			escaped = true
		case c == '"':
			b.WriteByte(c)
			inString = false
		case c < 0x20:
			fmt.Fprintf(&b, `\u%04x`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func decodeText(data []byte, enc string) (string, error) {
	switch enc {
	case "utf-8":
		return string(data), nil
	case "latin-1":
		runes := make([]rune, len(data))
		for i, b := range data {
			runes[i] = rune(b)
		}
		return string(runes), nil
	case "utf-16-le":
		if len(data)%2 != 0 {
			return "", errors.New("odd-length UTF-16LE input")
		}
		u16 := make([]uint16, len(data)/2)
		for i := range u16 {
			u16[i] = uint16(data[2*i]) | uint16(data[2*i+1])<<8
		}
		return string(utf16.Decode(u16)), nil
	default:
		return "", fmt.Errorf("unknown encoding %q", enc)
	}
}

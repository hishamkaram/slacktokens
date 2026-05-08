// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

package slacktokens

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestDeriveKey_LinuxV10ConstantMatches(t *testing.T) {
	got := deriveKey([]byte("peanuts"), 1)
	if !bytes.Equal(got, linuxV10Key) {
		t.Fatalf("derived key %x != hardcoded linuxV10Key %x", got, linuxV10Key)
	}
}

func TestDecryptCookieValue_V10_RoundTrip_NoSHA(t *testing.T) {
	plaintext := []byte("xoxd-test-value")
	enc, err := encryptCookieValueV10(plaintext, linuxV10Key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := decryptCookieValue(enc, linuxV10Key, nil, 0)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestDecryptCookieValue_V10_RoundTrip_WithSHAPrefix(t *testing.T) {
	hostKey := ".slack.com"
	cookieValue := []byte("xoxd-with-prefix")
	sum := sha256.Sum256([]byte(hostKey))
	plaintextWithPrefix := append(sum[:], cookieValue...)
	enc, err := encryptCookieValueV10(plaintextWithPrefix, linuxV10Key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	got, err := decryptCookieValue(enc, linuxV10Key, nil, 24)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != string(cookieValue) {
		t.Fatalf("got %q want %q", got, cookieValue)
	}
}

func TestDecryptCookieValue_V11_NoKey(t *testing.T) {
	enc := append([]byte("v11"), bytes.Repeat([]byte{0x42}, 16)...)
	_, err := decryptCookieValue(enc, linuxV10Key, nil, 0)
	if err == nil {
		t.Fatal("expected error when v11 key is nil")
	}
}

func TestDecryptCookieValue_UnknownPrefix(t *testing.T) {
	enc := append([]byte("v99"), bytes.Repeat([]byte{0x42}, 16)...)
	if _, err := decryptCookieValue(enc, linuxV10Key, linuxV10Key, 0); err == nil {
		t.Fatal("expected error for unknown prefix")
	}
}

func TestDecryptCookieValue_TooShort(t *testing.T) {
	if _, err := decryptCookieValue([]byte("xx"), linuxV10Key, nil, 0); err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestPkcs7UnpadRejectsBadPadding(t *testing.T) {
	bad := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff}
	if _, err := pkcs7Unpad(bad, 16); err == nil {
		t.Fatal("expected error for impossible padding length")
	}
}

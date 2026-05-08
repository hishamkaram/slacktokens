package slacktokens

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// chromiumIV is the fixed IV that Chromium uses for cookie encryption: 16
// ASCII space characters. Source: components/os_crypt/async/common/encryptor.cc
// in Chromium main (verified 2026-05-08).
var chromiumIV = bytes.Repeat([]byte{0x20}, 16)

// chromiumSalt is the PBKDF2 salt Chromium uses across all platforms.
var chromiumSalt = []byte("saltysalt")

// linuxV10Key is the precomputed AES key for Linux v10 cookies.
//   PBKDF2-HMAC-SHA1("peanuts", "saltysalt", 1, 16)
// Hardcoded in Chromium's posix_key_provider.cc.
var linuxV10Key = []byte{
	0xfd, 0x62, 0x1f, 0xe5, 0xa2, 0xb4, 0x02, 0x53,
	0x9d, 0xfa, 0x14, 0x7c, 0xa9, 0x27, 0x27, 0x78,
}

// deriveKey runs PBKDF2-HMAC-SHA1 with Chromium's salt and a 16-byte output.
func deriveKey(password []byte, iterations int) []byte {
	return pbkdf2.Key(password, chromiumSalt, iterations, 16, sha1.New)
}

// decryptCookieValue decrypts one Chromium-encrypted cookie value.
//
// `encrypted` is the raw bytes from the cookies.encrypted_value column.
// `keyV10` is the AES key to use for v10-prefixed values.
// `keyV11` is the AES key to use for v11-prefixed values (may be nil on macOS).
// `metaVersion` is the cookies SQLite meta.version (>=24 means a 32-byte SHA-256
// of host_key prefixes the plaintext).
func decryptCookieValue(encrypted, keyV10, keyV11 []byte, metaVersion int) (string, error) {
	if len(encrypted) < 3 {
		return "", errors.New("encrypted value too short")
	}
	prefix := string(encrypted[:3])
	body := encrypted[3:]
	var key []byte
	switch prefix {
	case "v10":
		key = keyV10
	case "v11":
		if keyV11 == nil {
			return "", fmt.Errorf("v11 key unavailable for this platform")
		}
		key = keyV11
	default:
		return "", fmt.Errorf("unknown cookie encryption prefix %q", prefix)
	}
	if len(key) != 16 {
		return "", fmt.Errorf("invalid key length %d", len(key))
	}
	if len(body)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext not a multiple of block size: %d", len(body))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, chromiumIV).CryptBlocks(plain, body)
	plain, err = pkcs7Unpad(plain, aes.BlockSize)
	if err != nil {
		return "", fmt.Errorf("unpad: %w", err)
	}
	if metaVersion >= 24 {
		if len(plain) < 32 {
			return "", errors.New("plaintext shorter than SHA-256 prefix")
		}
		plain = plain[32:]
	}
	return string(plain), nil
}

func pkcs7Unpad(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, fmt.Errorf("invalid padded length %d", len(b))
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > blockSize {
		return nil, fmt.Errorf("invalid padding byte %d", pad)
	}
	for i := len(b) - pad; i < len(b); i++ {
		if int(b[i]) != pad {
			return nil, errors.New("padding bytes inconsistent")
		}
	}
	return b[:len(b)-pad], nil
}

// pkcs7Pad is exposed for tests that need to construct a v10 fixture.
func pkcs7Pad(b []byte, blockSize int) []byte {
	pad := blockSize - len(b)%blockSize
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// encryptCookieValueV10 is for tests only — produces a fixture row that
// decryptCookieValue can round-trip.
func encryptCookieValueV10(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	enc := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, chromiumIV).CryptBlocks(enc, padded)
	return append([]byte("v10"), enc...), nil
}

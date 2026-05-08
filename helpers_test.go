package slacktokens

import (
	"crypto/aes"
	"crypto/cipher"
)

// encryptCookieValueV10 is a test helper that produces a v10-prefixed
// ciphertext that decryptCookieValue can round-trip. Lives in a _test.go file
// so the production binary doesn't ship the encrypt path (and so gosec G407
// doesn't flag the fixed Chromium IV in non-test code).
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

func pkcs7Pad(b []byte, blockSize int) []byte {
	pad := blockSize - len(b)%blockSize
	out := make([]byte, len(b)+pad)
	copy(out, b)
	padByte := byte(pad & 0xFF)
	for i := len(b); i < len(out); i++ {
		out[i] = padByte
	}
	return out
}

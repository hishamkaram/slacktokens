//go:build !darwin && !linux

package slacktokens

func systemKeychainPassword() (string, error) {
	return "", ErrUnsupportedOS
}

func platformCookieKeys() (keyV10, keyV11 []byte, err error) {
	return nil, nil, ErrUnsupportedOS
}

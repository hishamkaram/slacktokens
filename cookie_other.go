// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

//go:build !darwin && !linux && !windows

package slacktokens

func systemKeychainPassword() (string, error) {
	return "", ErrUnsupportedOS
}

func newPlatformDecrypter() (cookieDecrypter, error) {
	return nil, ErrUnsupportedOS
}

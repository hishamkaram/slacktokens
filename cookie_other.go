// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

//go:build !darwin && !linux && !windows

package slacktokens

import "os"

func systemKeychainPassword() (string, error) {
	return "", ErrUnsupportedOS
}

func newPlatformDecrypter(_ *os.Root) (cookieDecrypter, error) {
	return nil, ErrUnsupportedOS
}

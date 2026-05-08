// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm
// Derived from slacktokens (Python, GPL-3.0) by Heath Raftery, 2021.

//go:build linux

package slacktokens

import (
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
)

const (
	secretServicePath  = "/org/freedesktop/secrets"
	secretServiceIface = "org.freedesktop.Secret.Service"

	// Chromium libsecret schema name (current as of Chromium 148).
	chromiumLibsecretSchema = "chrome_libsecret_os_crypt_password_v2"
)

// systemKeychainPassword reads the Slack Safe Storage password from libsecret
// via D-Bus Secret Service API. Returns the v11 password.
func systemKeychainPassword() (string, error) {
	bus, err := dbus.SessionBus()
	if err != nil {
		return "", fmt.Errorf("connect dbus session: %w", err)
	}
	svc := bus.Object("org.freedesktop.secrets", dbus.ObjectPath(secretServicePath))

	// Try matching by both schema and application=Slack. We probe a few
	// attribute combinations because Chromium has churned across versions.
	attempts := []map[string]string{
		{"xdg:schema": chromiumLibsecretSchema, "application": "Slack"},
		{"xdg:schema": chromiumLibsecretSchema, "application": "slack"},
		{"application": "Slack"},
		{"application": "slack"},
	}

	var session dbus.ObjectPath
	if err := svc.Call(secretServiceIface+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(new(dbus.Variant), &session); err != nil {
		return "", fmt.Errorf("open libsecret session: %w", err)
	}
	defer svc.Call(secretServiceIface+".Close", 0)

	for _, attrs := range attempts {
		var unlocked, locked []dbus.ObjectPath
		if err := svc.Call(secretServiceIface+".SearchItems", 0, attrs).Store(&unlocked, &locked); err != nil {
			continue
		}
		paths := append([]dbus.ObjectPath{}, unlocked...)
		if len(locked) > 0 {
			var prompt dbus.ObjectPath
			var unlockedNow []dbus.ObjectPath
			if err := svc.Call(secretServiceIface+".Unlock", 0, locked).Store(&unlockedNow, &prompt); err == nil {
				paths = append(paths, unlockedNow...)
			}
		}
		for _, p := range paths {
			item := bus.Object("org.freedesktop.secrets", p)
			var secret struct {
				Session     dbus.ObjectPath
				Parameters  []byte
				Value       []byte
				ContentType string
			}
			if err := item.Call("org.freedesktop.Secret.Item.GetSecret", 0, session).Store(&secret); err == nil {
				if len(secret.Value) > 0 {
					return string(secret.Value), nil
				}
			}
		}
	}

	return "", errors.New("slack Safe Storage not found via libsecret/Secret Service")
}

// newPlatformDecrypter wires up the Linux cookie decrypt strategy:
// libsecret password -> PBKDF2(1 iter) -> AES-128-CBC for v11. v10 cookies
// (rare; written when the keyring is unavailable) use the precomputed
// linuxV10Key. If libsecret is unreachable we still try v10.
func newPlatformDecrypter() (cookieDecrypter, error) {
	keyV10 := linuxV10Key
	var keyV11 []byte
	if pw, err := keychainPasswordFn(); err == nil {
		keyV11 = deriveKey([]byte(pw), 1)
	}
	return func(enc []byte, _ string, metaVersion int) (string, error) {
		return decryptCookieValueCBC(enc, keyV10, keyV11, metaVersion)
	}, nil
}

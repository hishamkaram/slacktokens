// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

//go:build windows

package slacktokens

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dataBlob mirrors Win32's DATA_BLOB used by CryptProtectData / CryptUnprotectData.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newDataBlob(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		cbData: uint32(len(b)),
		pbData: &b[0],
	}
}

func (b *dataBlob) bytes() []byte {
	if b.cbData == 0 || b.pbData == nil {
		return nil
	}
	out := make([]byte, b.cbData)
	src := unsafe.Slice(b.pbData, b.cbData)
	copy(out, src)
	return out
}

var (
	modCrypt32             = windows.NewLazySystemDLL("crypt32.dll")
	procCryptUnprotectData = modCrypt32.NewProc("CryptUnprotectData")
)

// dpapiUnprotect calls Win32 CryptUnprotectData on `in` in the current user
// context (no entropy, no UI). Returns the unwrapped plaintext.
func dpapiUnprotect(in []byte) ([]byte, error) {
	var out dataBlob
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(newDataBlob(in))),
		0, // ppszDataDescr
		0, // pOptionalEntropy
		0, // pvReserved
		0, // pPromptStruct
		0, // dwFlags
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer func() {
		if out.pbData != nil {
			_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.pbData)))
		}
	}()
	return out.bytes(), nil
}

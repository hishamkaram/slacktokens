// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

//go:build unix

package main

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestOpenUploadFileRejectsFIFOWithoutBlocking guards against a hang: a
// blocking open of a FIFO with no writer never returns, so the tool call could
// not finish or be cancelled.
func TestOpenUploadFileRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	h := &handlers{cfg: mcpConfig{uploadRoot: root}}
	done := make(chan error, 1)
	go func() {
		f, _, err := h.openUploadFile("pipe")
		if err == nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("opened a FIFO as an upload candidate")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("openUploadFile blocked on a FIFO with no writer")
	}
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

//go:build unix

package main

import (
	"os"
	"syscall"
)

// uploadOpenFlag opens upload candidates without blocking. Opening a FIFO that
// has no writer would otherwise block before the regular-file check runs, and
// context cancellation cannot interrupt that open. O_NONBLOCK does not change
// reads from regular files.
const uploadOpenFlag = os.O_RDONLY | syscall.O_NONBLOCK

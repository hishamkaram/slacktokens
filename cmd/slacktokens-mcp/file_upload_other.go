// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Hesham Karm

//go:build !unix

package main

import "os"

// uploadOpenFlag is a plain read-only open. These platforms have no FIFOs in
// the filesystem namespace, so opening an upload candidate cannot block on one.
const uploadOpenFlag = os.O_RDONLY

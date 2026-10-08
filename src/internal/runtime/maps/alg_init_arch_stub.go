// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !(s390x)

package maps

// algInitArch is called from AlgInit to perform any architecture-specific
// hash initialization not covered by the amd64/arm64/386 AES paths.
// This stub is used for all architectures except s390x.
func algInitArch() {}

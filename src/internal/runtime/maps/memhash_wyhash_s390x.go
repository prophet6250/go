// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build s390x

// Vectorized wyhash for s390x using VMSLG (VECTOR MULTIPLY SUM LOGICAL).
//
// The wyhash mix function is:
//   mix(a, b) = hi(a*b) XOR lo(a*b)
//
// On s390x we implement this using the VX facility's VMSLG instruction, which
// computes the full 128-bit product of two 64-bit lane pairs into a 128-bit
// result register. We then XOR the high and low 64-bit halves.
//
// This is the s390x analogue of the AES-NI path on amd64/arm64: the loop
// structure and size thresholds mirror the scalar wyhash fallback, but each
// mix() call is replaced by a vector multiply in the assembly.
//
// Requires the VX (vector facility) which is present on all z13+ machines.
// The VX capability bit is checked at runtime; we fall back to the pure-Go
// scalar wyhash when VX is not available (very old KVM guests).

package maps

import (
	"internal/cpu"
	"unsafe"
)

// These constants mirror the ones in memhash_noaes.go / memhash_aes.go so that
// the export_test.go MemHashAES shim compiles on s390x too.
const memHashAESImplemented = false
const memHashUsesVAES = false

func memHash32AES(k uint32, h uintptr) uintptr {
	panic("memHash32AES not implemented on s390x")
}

func memHash64AES(k uint64, h uintptr) uintptr {
	panic("memHash64AES not implemented on s390x")
}

func memHashAES(p unsafe.Pointer, h, s uintptr) uintptr {
	panic("memHashAES not implemented on s390x")
}

// memHashVX is the s390x VX-accelerated wyhash implementation.
// Provided by memhash_s390x.s.
//
//go:noescape
func memHashVX(p unsafe.Pointer, h, s uintptr) uintptr

// useVXhash is set to true in initAlgVX when the VX facility is detected.
var useVXhash bool

// algInitArch is called from AlgInit. For s390x it enables the VX-based
// wyhash when the vector facility (z13+) is available.
func algInitArch() {
	if cpu.S390X.HasVX {
		// VX path is faster than scalar wyhash for inputs ≥ 16 bytes.
		// Below 16 bytes the scalar fallback wins on latency.
		// TODO: tune per-microarchitecture (z13/z14/z15/z16/z17).
		useVXhash = true
		MinAeshashSize = 16
	}
}

// MemHash dispatches to the VX wyhash or the scalar fallback.
func MemHash(p unsafe.Pointer, h, s uintptr) uintptr {
	if s >= MinAeshashSize {
		return memHashVX(p, h, s)
	}
	return memHashFallback(p, h, s)
}

func MemHash32(k uint32, h uintptr) uintptr {
	return memHash32Fallback(k, h)
}

func MemHash64(k uint64, h uintptr) uintptr {
	return memHash64Fallback(k, h)
}

func StrHash(s string, h uintptr) uintptr {
	return MemHash(unsafe.Pointer(unsafe.StringData(s)), h, uintptr(len(s)))
}

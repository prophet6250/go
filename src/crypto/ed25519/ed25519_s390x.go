// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !purego

package ed25519

import (
	"internal/cpu"
	"strconv"
)

//go:noescape
func kdsaSign(message, signature, privateKey []byte) bool

//go:noescape
func kdsaVerify(message, signature, publicKey []byte) bool

// sign does a check to see if hardware has Edwards Curve instruction available.
// If it does, use the hardware implementation. Otherwise, use the generic version.
func sign(signature, privateKey, message []byte) {
	if cpu.S390X.HasEDDSA {
		if l := len(privateKey); l != PrivateKeySize {
			panic("ed25519: bad private key length: " + strconv.Itoa(l))
		}

		ret := kdsaSign(message, signature, privateKey[:32])
		if !ret {
			panic("ed25519: kdsa sign has a failure")
		}
		return
	}
	signGeneric(signature, privateKey, message)
}

// verify does a check to see if hardware has Edwards Curve instruction available.
// If it does, use the hardware implementation for eddsa verification. Otherwise, the generic
// version is used.
func verify(publicKey PublicKey, message, sig []byte) bool {
	if cpu.S390X.HasEDDSA {
		if l := len(publicKey); l != PublicKeySize {
			panic("ed25519: bad public key length: " + strconv.Itoa(l))
		}

		if len(sig) != SignatureSize || sig[63]&224 != 0 {
			return false
		}

		ret := kdsaVerify(message, sig, publicKey)

		// KDSA applies stricter input validation than RFC 8032 requires and may
		// reject signatures that the pure-Go implementation accepts as valid.
		// To keep the two code paths consistent, verifyGeneric is used as the
		// authoritative answer whenever KDSA rejects a signature. Valid signatures
		// (the common case) are confirmed by KDSA and the second check is skipped,
		// so there is no performance cost on the hot path.
		if !ret {
			ret = verifyGeneric(publicKey, message, sig)
		}

		return ret
	}
	return verifyGeneric(publicKey, message, sig)
}

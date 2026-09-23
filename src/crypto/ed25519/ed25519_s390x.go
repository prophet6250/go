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

//go:noescape
func kdsaVerifyCC(message, signature, publicKey []byte) uint8

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

		return kdsaVerify(message, sig, publicKey)
	}
	return verifyGeneric(publicKey, message, sig)
}

// verifyWithCC is the instrumentation-only path. It returns (result, cc) where
// cc is the raw KDSA condition code (0=valid, 1=key invalid, 2=sig invalid).
// On non-s390x or when EDDSA is not available, cc is always 0.
func verifyWithCC(publicKey PublicKey, message, sig []byte) (bool, uint8) {
	if cpu.S390X.HasEDDSA {
		if l := len(publicKey); l != PublicKeySize {
			panic("ed25519: bad public key length: " + strconv.Itoa(l))
		}
		if len(sig) != SignatureSize || sig[63]&224 != 0 {
			return false, 255 // pre-check rejection, no KDSA call
		}
		cc := kdsaVerifyCC(message, sig, publicKey)
		return cc == 0, cc
	}
	return verifyGeneric(publicKey, message, sig), 0
}

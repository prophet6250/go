// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !s390x || purego

package ed25519

func sign(signature, privateKey, message []byte) {
	signGeneric(signature, privateKey, message)
}

func verify(publicKey PublicKey, message, sig []byte) bool {
	return verifyGeneric(publicKey, message, sig)
}

// verifyWithCC is the non-s390x stub. It delegates to verifyGeneric and
// always returns cc=0 because there is no KDSA instruction to interrogate.
func verifyWithCC(publicKey PublicKey, message, sig []byte) (bool, uint8) {
	return verifyGeneric(publicKey, message, sig), 0
}

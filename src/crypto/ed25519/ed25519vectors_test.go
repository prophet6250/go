// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ed25519_test

import (
	"crypto/ed25519"
	"crypto/internal/cryptotest"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ccDescription maps raw KDSA condition codes to human-readable labels.
// cc=255 is a sentinel used by verifyWithCC to indicate the signature was
// rejected by the Go pre-check before KDSA was ever invoked.
func ccDescription(cc uint8) string {
	switch cc {
	case 0:
		return "CC=0 (valid)"
	case 1:
		return "CC=1 (public key invalid: not decompressable, Y >= prime, or not on curve)"
	case 2:
		return "CC=2 (signature invalid: R/S out of range, or signature mismatch)"
	case 3:
		return "CC=3 (partial completion — should not appear, retry loop handles this)"
	case 255:
		return "CC=n/a (rejected by Go pre-check: bad sig length or high-bits set)"
	default:
		return fmt.Sprintf("CC=%d (unknown)", cc)
	}
}

// TestEd25519Vectors runs a very large set of test vectors that exercise all
// combinations of low-order points, low-order components, and non-canonical
// encodings. These vectors lock in unspecified and spec-divergent behaviors in
// edge cases that are not security relevant in most contexts, but that can
// cause issues in consensus applications if changed.
//
// Our behavior matches the "classic" unwritten verification rules of the
// "ref10" reference implementation.
//
// Note that although we test for these edge cases, they are not covered by the
// Go 1 Compatibility Promise. Applications that need stable verification rules
// should use github.com/hdevalence/ed25519consensus.
//
// See https://hdevalence.ca/blog/2020-10-04-its-25519am for more details.
func TestEd25519Vectors(t *testing.T) {
	jsonVectors := downloadEd25519Vectors(t)
	var vectors []struct {
		A, R, S, M string
		Flags      []string
	}
	if err := json.Unmarshal(jsonVectors, &vectors); err != nil {
		t.Fatal(err)
	}

	isS390X := runtime.GOARCH == "s390x"

	for i, v := range vectors {
		expectedToVerify := true
		for _, f := range v.Flags {
			switch f {
			// We use the simplified verification formula that doesn't multiply
			// by the cofactor, so any low order residue will cause the
			// signature not to verify.
			//
			// This is allowed, but not required, by RFC 8032.
			case "LowOrderResidue":
				expectedToVerify = false
			// Our point decoding allows non-canonical encodings (in violation
			// of RFC 8032) but R is not decoded: instead, R is recomputed and
			// compared bytewise against the canonical encoding.
			case "NonCanonicalR":
				expectedToVerify = false
			}
		}

		publicKey := decodeHex(t, v.A)
		signature := append(decodeHex(t, v.R), decodeHex(t, v.S)...)
		message := []byte(v.M)

		// verifyWithCC calls the KDSA instruction directly on s390x and
		// returns the raw condition code for diagnostic purposes.
		// On all other architectures it delegates to the generic implementation
		// and returns cc=0.
		didVerify, cc := ed25519.VerifyWithCC(publicKey, message, signature)

		if isS390X {
			// On s390x, log every vector so we can see the CC distribution.
			// Suppress the per-vector log in normal runs; surface it only on
			// mismatch or via -v so the output stays manageable.
			if didVerify != expectedToVerify || testing.Verbose() {
				t.Logf("[%d] flags=%-20v pubkey=%.16s… expected=%v got=%v %s",
					i, v.Flags, v.A, expectedToVerify, didVerify, ccDescription(cc))
			}
		}

		if didVerify && !expectedToVerify {
			t.Errorf("[%d] flags=%v: unexpectedly verified  pubkey=%s sig=%.64s… message=%q  %s",
				i, v.Flags, v.A, hex.EncodeToString(signature), v.M, ccDescription(cc))
		}
		if !didVerify && expectedToVerify {
			t.Errorf("[%d] flags=%v: unexpectedly rejected  pubkey=%s sig=%.64s… message=%q  %s",
				i, v.Flags, v.A, hex.EncodeToString(signature), v.M, ccDescription(cc))
		}
	}
}

func downloadEd25519Vectors(t *testing.T) []byte {
	// Download the JSON test file from the GOPROXY with `go mod download`,
	// pinning the version so test and module caching works as expected.
	path := "filippo.io/mostly-harmless/ed25519vectors"
	version := "v0.0.0-20210322192420-30a2d7243a94"
	dir := cryptotest.FetchModule(t, path, version)

	jsonVectors, err := os.ReadFile(filepath.Join(dir, "ed25519vectors.json"))
	if err != nil {
		t.Fatalf("failed to read ed25519vectors.json: %v", err)
	}
	return jsonVectors
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Errorf("invalid hex: %v", err)
	}
	return b
}

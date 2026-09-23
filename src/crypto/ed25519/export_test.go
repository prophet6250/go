// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// export_test.go exposes internal symbols to external test packages.
// This file is only compiled during testing.

package ed25519

// VerifyWithCC exposes the internal verifyWithCC function for diagnostic
// instrumentation in tests. It returns (verified bool, cc uint8) where cc is
// the raw KDSA condition code on s390x (0=valid, 1=key invalid, 2=sig invalid,
// 255=pre-check rejection before KDSA call) and always 0 on other platforms.
var VerifyWithCC = verifyWithCC

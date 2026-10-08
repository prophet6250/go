// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Vectorized wyhash for s390x using VMSLG (VECTOR MULTIPLY SUM LOGICAL).
//
// mix(a, b) = hi(a*b) XOR lo(a*b).
//
// VMSLG V_a, V_b, V_acc, V_res:
//   lane-0(V_a) × lane-0(V_b) → 128-bit intermediate 1
//   lane-1(V_a) × lane-1(V_b) → 128-bit intermediate 2
//   V_res = intermediate1 + intermediate2 + V_acc
//
// Zeroing lane-1 of both operands and V_acc gives V_res={hi(a*b),lo(a*b)}.
// VLGVG $0 → hi64, VLGVG $1 → lo64.  mix = hi XOR lo.
//
// ABIInternal: R2=p, R3=h(seed), R4=s(len) → return in R2.
// R0, R1 are volatile scratch. V0-V7, V16-V31 are volatile.

#include "textflag.h"

// mixregs(Ra, Rb): Ra = hi(Ra*Rb) XOR lo(Ra*Rb). Clobbers V16-V19, R0.
// Fully inlined; no macros.
#define mixregs(Ra, Rb) \
	VZERO  V18                \
	VZERO  V16                \
	VZERO  V17                \
	VLVGG  $0, Ra, V16        \
	VLVGG  $0, Rb, V17        \
	VMSLG  V16, V17, V18, V19 \
	VLGVG  $0, V19, Ra        \
	VLGVG  $1, V19, R0        \
	XOR    R0, Ra

// func memHashVX(p unsafe.Pointer, h, s uintptr) uintptr
TEXT ·memHashVX(SB),NOSPLIT,$0-32
	// FP-based ABI: p+0(FP), h+8(FP), s+16(FP), ret+24(FP)
	MOVD   p+0(FP), R2
	MOVD   h+8(FP), R3
	MOVD   s+16(FP), R4

	// seed ^= hashkey[0]
	MOVD   ·hashkey+0(SB), R5
	XOR    R5, R3

	CMPBEQ R4, $0, wyh_zero
	CMPBLT R4, $4, wyh_1to3
	CMPBEQ R4, $4, wyh_4
	CMPBLT R4, $8, wyh_5to7
	CMPBEQ R4, $8, wyh_8
	CMPBLE R4, $16, wyh_9to16
	CMPBLE R4, $48, wyh_17to48

	// s > 48
	MOVD   R3, R6  // seed1 = seed
	MOVD   R3, R7  // seed2 = seed
wyh_loop48:
	MOVD   ·hashkey+8(SB), R8
	MOVD   ·hashkey+16(SB), R9
	MOVD   ·hashkey+24(SB), R10
	MOVD   0(R2), R11
	XOR    R8, R11
	MOVD   8(R2), R12
	XOR    R3, R12
	mixregs(R11, R12)
	MOVD   R11, R3
	MOVD   16(R2), R11
	XOR    R9, R11
	MOVD   24(R2), R12
	XOR    R6, R12
	mixregs(R11, R12)
	MOVD   R11, R6
	MOVD   32(R2), R11
	XOR    R10, R11
	MOVD   40(R2), R12
	XOR    R7, R12
	mixregs(R11, R12)
	MOVD   R11, R7
	ADD    $48, R2
	ADD    $-48, R4
	CMPBGT R4, $48, wyh_loop48
	XOR    R6, R3
	XOR    R7, R3

wyh_17to48:
wyh_loop16:
	CMPBLE R4, $16, wyh_tail16
	MOVD   ·hashkey+8(SB), R8
	MOVD   0(R2), R11
	XOR    R8, R11
	MOVD   8(R2), R12
	XOR    R3, R12
	mixregs(R11, R12)
	MOVD   R11, R3
	ADD    $16, R2
	ADD    $-16, R4
	JMP    wyh_loop16

wyh_tail16:
	ADD    R4, R2, R8
	MOVD   -16(R8), R11
	MOVD   -8(R8), R12
	MOVD   ·hashkey+8(SB), R5
	XOR    R5, R11
	XOR    R3, R12
	mixregs(R11, R12)
	MOVD   $0x1d8e4e27c47d124f, R1
	XOR    R4, R1
	mixregs(R1, R11)
	MOVD   R1, ret+24(FP)
	RET

wyh_9to16:
	MOVD   0(R2), R11
	ADD    R4, R2, R8
	MOVD   -8(R8), R12
	MOVD   ·hashkey+8(SB), R5
	XOR    R5, R11
	XOR    R3, R12
	mixregs(R11, R12)
	MOVD   $0x1d8e4e27c47d124f, R1
	XOR    R4, R1
	mixregs(R1, R11)
	MOVD   R1, ret+24(FP)
	RET

wyh_8:
	MOVD   0(R2), R11
	MOVD   R11, R12
	MOVD   ·hashkey+8(SB), R5
	XOR    R5, R11
	XOR    R3, R12
	mixregs(R11, R12)
	MOVD   $0x1d8e4e27c47d124f, R1
	XOR    R4, R1
	mixregs(R1, R11)
	MOVD   R1, ret+24(FP)
	RET

wyh_5to7:
	MOVWZ  0(R2), R11
	ADD    R4, R2, R8
	MOVWZ  -4(R8), R12
	MOVD   ·hashkey+8(SB), R5
	XOR    R5, R11
	XOR    R3, R12
	mixregs(R11, R12)
	MOVD   $0x1d8e4e27c47d124f, R1
	XOR    R4, R1
	mixregs(R1, R11)
	MOVD   R1, ret+24(FP)
	RET

wyh_4:
	MOVWZ  0(R2), R11
	MOVD   R11, R12
	MOVD   ·hashkey+8(SB), R5
	XOR    R5, R11
	XOR    R3, R12
	mixregs(R11, R12)
	MOVD   $0x1d8e4e27c47d124f, R1
	XOR    R4, R1
	mixregs(R1, R11)
	MOVD   R1, ret+24(FP)
	RET

wyh_1to3:
	// a = byte[0] | byte[s>>1]<<8 | byte[s-1]<<16
	MOVBZ  0(R2), R11
	ADD    R4, R2, R8
	MOVBZ  -1(R8), R1
	SLD    $16, R1
	OR     R1, R11
	SRD    $1, R4, R1
	MOVBZ  (R2)(R1*1), R1
	SLD    $8, R1
	OR     R1, R11
	MOVD   $0, R12
	MOVD   ·hashkey+8(SB), R5
	XOR    R5, R11
	XOR    R3, R12
	mixregs(R11, R12)
	MOVD   $0x1d8e4e27c47d124f, R1
	XOR    R4, R1
	mixregs(R1, R11)
	MOVD   R1, ret+24(FP)
	RET

wyh_zero:
	MOVD   R3, ret+24(FP)
	RET

/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

.attribute arch, "rv64imafdc"

.macro DEFINE_SAVE_FPU name, suffix, width
    .global save_fpu_\name
    .type save_fpu_\name,@function
    save_fpu_\name:
        li t0, 1 << 13
        csrs sstatus, t0
        fs\suffix f0, 0 * \width(a0)
        fs\suffix f1, 1 * \width(a0)
        fs\suffix f2, 2 * \width(a0)
        fs\suffix f3, 3 * \width(a0)
        fs\suffix f4, 4 * \width(a0)
        fs\suffix f5, 5 * \width(a0)
        fs\suffix f6, 6 * \width(a0)
        fs\suffix f7, 7 * \width(a0)
        fs\suffix f8, 8 * \width(a0)
        fs\suffix f9, 9 * \width(a0)
        fs\suffix f10, 10 * \width(a0)
        fs\suffix f11, 11 * \width(a0)
        fs\suffix f12, 12 * \width(a0)
        fs\suffix f13, 13 * \width(a0)
        fs\suffix f14, 14 * \width(a0)
        fs\suffix f15, 15 * \width(a0)
        fs\suffix f16, 16 * \width(a0)
        fs\suffix f17, 17 * \width(a0)
        fs\suffix f18, 18 * \width(a0)
        fs\suffix f19, 19 * \width(a0)
        fs\suffix f20, 20 * \width(a0)
        fs\suffix f21, 21 * \width(a0)
        fs\suffix f22, 22 * \width(a0)
        fs\suffix f23, 23 * \width(a0)
        fs\suffix f24, 24 * \width(a0)
        fs\suffix f25, 25 * \width(a0)
        fs\suffix f26, 26 * \width(a0)
        fs\suffix f27, 27 * \width(a0)
        fs\suffix f28, 28 * \width(a0)
        fs\suffix f29, 29 * \width(a0)
        fs\suffix f30, 30 * \width(a0)
        fs\suffix f31, 31 * \width(a0)
        frcsr t0
        sw t0, 32 * \width(a0)
        ret
.endm

.macro DEFINE_RESTORE_FPU name, suffix, width
    .global restore_fpu_\name
    .type restore_fpu_\name,@function
    restore_fpu_\name:
        li t0, 1 << 13
        csrs sstatus, t0
        fl\suffix f0, 0 * \width(a0)
        fl\suffix f1, 1 * \width(a0)
        fl\suffix f2, 2 * \width(a0)
        fl\suffix f3, 3 * \width(a0)
        fl\suffix f4, 4 * \width(a0)
        fl\suffix f5, 5 * \width(a0)
        fl\suffix f6, 6 * \width(a0)
        fl\suffix f7, 7 * \width(a0)
        fl\suffix f8, 8 * \width(a0)
        fl\suffix f9, 9 * \width(a0)
        fl\suffix f10, 10 * \width(a0)
        fl\suffix f11, 11 * \width(a0)
        fl\suffix f12, 12 * \width(a0)
        fl\suffix f13, 13 * \width(a0)
        fl\suffix f14, 14 * \width(a0)
        fl\suffix f15, 15 * \width(a0)
        fl\suffix f16, 16 * \width(a0)
        fl\suffix f17, 17 * \width(a0)
        fl\suffix f18, 18 * \width(a0)
        fl\suffix f19, 19 * \width(a0)
        fl\suffix f20, 20 * \width(a0)
        fl\suffix f21, 21 * \width(a0)
        fl\suffix f22, 22 * \width(a0)
        fl\suffix f23, 23 * \width(a0)
        fl\suffix f24, 24 * \width(a0)
        fl\suffix f25, 25 * \width(a0)
        fl\suffix f26, 26 * \width(a0)
        fl\suffix f27, 27 * \width(a0)
        fl\suffix f28, 28 * \width(a0)
        fl\suffix f29, 29 * \width(a0)
        fl\suffix f30, 30 * \width(a0)
        fl\suffix f31, 31 * \width(a0)
        ld t0, 32 * \width(a0)
        fscsr t0
        ret
.endm

# DEFINE_SAVE_FPU quad, q, 16
DEFINE_SAVE_FPU double, d, 8
DEFINE_SAVE_FPU single, w, 4
DEFINE_RESTORE_FPU double, d, 8
DEFINE_RESTORE_FPU single, w, 4

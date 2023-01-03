/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_RISCV_FEATURES_H
#define _ONYX_RISCV_FEATURES_H

#include <stdint.h>

#define RISCV_FEATURE_ATOMIC       (1 << 0)
#define RISCV_FEATURE_COMPRESSED   (1 << 2)
#define RISCV_FEATURE_DOUBLE_FP    (1 << 3)
#define RISCV_FEATURE_RV32E        (1 << 4)
#define RISCV_FEATURE_SINGLE_FP    (1 << 5)
#define RISCV_FEATURE_HYPERVISOR   (1 << 7)
#define RISCV_FEATURE_RV_INTEGER   (1 << 8)
#define RISCV_FEATURE_INT_MULT_DIV (1 << 12)
#define RISCV_FEATURE_QUAD_FP      (1 << 16)
#define RISCV_FEATURE_SUPERVISOR   (1 << 18)
#define RISCV_FEATURE_USER         (1 << 20)
#define RISCV_FEATURE_NONSTANDARD  (1 << 23)

/**
 * @brief Get the RISCV ISA features of the CPU
 *
 * @return A bitmask of the above defines
 */
uint32_t riscv_get_features();

/**
 * @brief Set the current hartid
 *
 * @param hart hartid
 */
void riscv_set_hartid(unsigned long hart);

/**
 * @brief Get the current hartid
 *
 * @return Current hartid
 */
unsigned long riscv_get_hartid();

#endif

/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _ONYX_RISCV_SBI_H
#define _ONYX_RISCV_SBI_H

#include <stdint.h>

struct sbiret
{
    long error;
    long value;
};

#define SBI_SUCCESS               0
#define SBI_ERR_FAILED            -1
#define SBI_ERR_NOT_SUPPORTED     -2
#define SBI_ERR_INVALID_PARAM     -3
#define SBI_ERR_DENIED            -4
#define SBI_ERR_INVALID_ADDRESS   -5
#define SBI_ERR_ALREADY_AVAILABLE -6
#define SBI_ERR_ALREADY_STARTED   -7
#define SBI_ERR_ALREADY_STOPPED   -8

#define SBI_GET_SPEC_VERSION     0
#define SBI_GET_SBI_IMPL_ID      1
#define SBI_GET_SBI_IMPL_VERSION 2
#define SBI_PROBE_EXTENSION      3
#define SBI_GET_MVENDORID        4
#define SBI_GET_MARCHID          5
#define SBI_GET_MIMPID           6

#define SBI_BASE_EXTENSION                  0x10
#define SBI_LEGACY_SET_TIMER_EXTENSION      0x00
#define SBI_TIMER_EXTENSION                 0x54494d45
#define SBI_SYSTEM_RESET_EXTENSION          0x53525354
#define SBI_HART_STATE_MANAGEMENT_EXTENSION 0x48534D
#define SBI_IPI_EXTENSION                   0x735049

// SBI timer extension functions
#define SBI_SET_TIMER 0

struct sbiret sbi_get_spec_version();
struct sbiret sbi_get_spec_impl_id();
struct sbiret sbi_get_spec_impl_version();
struct sbiret sbi_probe_extension(long extension_id);
void sbi_set_timer(uint64_t future);

#define SBI_SYSTEM_RESET_TYPE_SHUTDOWN    0
#define SBI_SYSTEM_RESET_TYPE_COLD_REBOOT 1
#define SBI_SYSTEM_RESET_TYPE_WARM_REBOOT 2

#define SBI_SYSTEM_RESET_REASON_NONE           0
#define SBI_SYSTEM_RESET_REASON_SYSTEM_FAILURE 1

void sbi_init();

long sbi_system_reset(uint32_t type, uint32_t reason);

long sbi_hart_start(unsigned long hartid, unsigned long start, unsigned long opaque);

long sbi_send_ipi(unsigned long hart_mask, unsigned long hart_mask_base);

/**
 * @brief Returns a string corresponding to the SBI error
 *
 * @param error SBI error
 * @return Pointer to string
 */
const char *sbi_strerror(long error);

#endif

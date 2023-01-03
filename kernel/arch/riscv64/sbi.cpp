/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/riscv/sbi.h>

// Stolen from lk, lk/sbi.c
/*
 * Copyright (c) 2015 Travis Geiselbrecht
 *
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT
 */
#define _sbi_call(extension, function, arg0, arg1, arg2, arg3, arg4, arg5, ...) \
    ({                                                                          \
        register unsigned long a0 asm("a0") = (unsigned long) arg0;             \
        register unsigned long a1 asm("a1") = (unsigned long) arg1;             \
        register unsigned long a2 asm("a2") = (unsigned long) arg2;             \
        register unsigned long a3 asm("a3") = (unsigned long) arg3;             \
        register unsigned long a4 asm("a4") = (unsigned long) arg4;             \
        register unsigned long a5 asm("a5") = (unsigned long) arg5;             \
        register unsigned long a6 asm("a6") = (unsigned long) function;         \
        register unsigned long a7 asm("a7") = (unsigned long) extension;        \
        asm volatile("ecall"                                                    \
                     : "+r"(a0), "+r"(a1)                                       \
                     : "r"(a2), "r"(a3), "r"(a4), "r"(a5), "r"(a6), "r"(a7)     \
                     : "memory");                                               \
        (struct sbiret){.error = (long) a0, .value = (long) a1};                \
    })

#define sbi_call(...) _sbi_call(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0)

struct sbiret sbi_get_spec_version()
{
    return sbi_call(SBI_BASE_EXTENSION, SBI_GET_SPEC_VERSION);
}

struct sbiret sbi_get_impl_id()
{
    return sbi_call(SBI_BASE_EXTENSION, SBI_GET_SBI_IMPL_ID);
}

struct sbiret sbi_get_impl_version()
{
    return sbi_call(SBI_BASE_EXTENSION, SBI_GET_SBI_IMPL_VERSION);
}

struct sbiret sbi_probe_extension(long extension_id)
{
    return sbi_call(SBI_BASE_EXTENSION, SBI_PROBE_EXTENSION, extension_id);
}

bool supports_timer_extension = false;
bool supports_reset_extension = false;
bool supports_hsm_extension = false;
bool supports_ipi_extension = false;

void sbi_set_timer(uint64_t future)
{
    if (supports_timer_extension)
        sbi_call(SBI_TIMER_EXTENSION, SBI_SET_TIMER, future);
    else
        sbi_call(SBI_LEGACY_SET_TIMER_EXTENSION, 0, future);
}

long sbi_system_reset(uint32_t type, uint32_t reason)
{
    if (!supports_reset_extension)
        return SBI_ERR_NOT_SUPPORTED;
    // Only returns on error
    return sbi_call(SBI_SYSTEM_RESET_EXTENSION, 0, type, reason).error;
}

long sbi_hart_start(unsigned long hartid, unsigned long start, unsigned long opaque)
{
    if (!supports_hsm_extension)
        return SBI_ERR_NOT_SUPPORTED;
    return sbi_call(SBI_HART_STATE_MANAGEMENT_EXTENSION, 0, hartid, start, opaque).error;
}

long sbi_send_ipi(unsigned long hart_mask, unsigned long hart_mask_base)
{
    if (!supports_ipi_extension)
        return SBI_ERR_NOT_SUPPORTED;
    return sbi_call(SBI_IPI_EXTENSION, 0, hart_mask, hart_mask_base).error;
}

void sbi_init()
{
    supports_timer_extension = (sbi_probe_extension(SBI_TIMER_EXTENSION).value != 0);
    supports_reset_extension = (sbi_probe_extension(SBI_SYSTEM_RESET_EXTENSION).value != 0);
    supports_hsm_extension = (sbi_probe_extension(SBI_HART_STATE_MANAGEMENT_EXTENSION).value != 0);
    supports_ipi_extension = (sbi_probe_extension(SBI_IPI_EXTENSION).value != 0);
}

const char *sbi_error_codes[] = {
    "Success",           "Failed",          "Not supported",
    "Invalid parameter", "Denied",          "Invalid address",
    "Already available", "Already started", "Already stopped",
};

/**
 * @brief Returns a string corresponding to the SBI error
 *
 * @param error SBI error
 * @return Pointer to string
 */
const char *sbi_strerror(long error)
{
    return sbi_error_codes[-error];
}

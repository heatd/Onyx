/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acqnx.h - OS specific defines, etc.
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACQNX_H__
#define __ACQNX_H__

#define ACPI_USE_STANDARD_HEADERS
#define ACPI_USE_SYSTEM_CLIBRARY

#define acpi_uintptr_t                  uintptr_t
#define ACPI_USE_LOCAL_CACHE
#define ACPI_CAST_PTHREAD_T(x)  ((acpi_thread_id) ACPI_TO_INTEGER (x))

/* At present time (QNX 6.6) all supported architectures are 32 bits. */
#define ACPI_MACHINE_WIDTH      32

#define COMPILER_DEPENDENT_INT64  int64_t
#define COMPILER_DEPENDENT_UINT64 uint64_t

#include <ctype.h>
#include <stdint.h>
#include <sys/neutrino.h>

#define __cli() interrupt_disable();
#define __sti() interrupt_enable();
#define __cdecl

#define ACPI_USE_NATIVE_DIVIDE
#define ACPI_USE_NATIVE_MATH64

#endif /* __ACQNX_H__ */

/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: achaiku.h - OS specific defines, etc. for Haiku (www.haiku-os.org)
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACHAIKU_H__
#define __ACHAIKU_H__

#define ACPI_USE_STANDARD_HEADERS
#define ACPI_USE_SYSTEM_CLIBRARY

#include <kernel_export.h>

struct mutex;


/* Host-dependent types and defines for user- and kernel-space ACPICA */

#define ACPI_MUTEX_TYPE             ACPI_OSL_MUTEX
#define acpi_mutex                          struct mutex *

#define ACPI_USE_NATIVE_DIVIDE
#define ACPI_USE_NATIVE_MATH64

/* #define acpi_thread_id                       thread_id */

#define acpi_semaphore                      sem_id
#define acpi_spinlock                       spinlock *
#define acpi_cpu_flags                      cpu_status

#define COMPILER_DEPENDENT_INT64    int64
#define COMPILER_DEPENDENT_UINT64   uint64


#ifdef B_HAIKU_64_BIT
#define ACPI_MACHINE_WIDTH          64
#else
#define ACPI_MACHINE_WIDTH          32
#endif


#ifdef _KERNEL_MODE
/* Host-dependent types and defines for in-kernel ACPICA */

/* ACPICA cache implementation is adequate. */
#define ACPI_USE_LOCAL_CACHE

#define ACPI_FLUSH_CPU_CACHE() __asm __volatile("wbinvd");

/* Based on free_BSD's due to lack of documentation */
extern int acpi_os_acquire_global_lock(uint32 *lock);
extern int acpi_os_release_global_lock(uint32 *lock);

#define ACPI_ACQUIRE_GLOBAL_LOCK(Glptr, acq)    do {                \
	 (acq) = acpi_os_acquire_global_lock(&((Glptr)->global_lock)); \
} while (0)

#define ACPI_RELEASE_GLOBAL_LOCK(Glptr, acq)    do {                \
		(acq) = acpi_os_release_global_lock(&((Glptr)->global_lock)); \
} while (0)

#else /* _KERNEL_MODE */
/* Host-dependent types and defines for user-space ACPICA */

#error "We only support kernel mode ACPI atm."

#endif /* _KERNEL_MODE */
#endif /* __ACHAIKU_H__ */

/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acdragonflyex.h - Extra OS specific defines, etc. for dragon_fly BSD
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACDRAGONFLYEX_H__
#define __ACDRAGONFLYEX_H__

#ifdef _KERNEL

#ifdef ACPI_DEBUG_CACHE
acpi_status
_acpi_os_release_object (
	acpi_cache_t                        *cache,
	void                                *object,
	const char                          *func,
	int                                 line);
#endif

#ifdef ACPI_DEBUG_LOCKS
acpi_cpu_flags
_acpi_os_acquire_lock (
	acpi_spinlock                       spin,
	const char                          *func,
	int                                 line);
#endif

#ifdef ACPI_DEBUG_MEMMAP
void *
_acpi_os_map_memory (
	acpi_physical_address               where,
	acpi_size                           length,
	const char                          *caller,
	int                                 line);

void
_acpi_os_unmap_memory (
	void                                *logical_address,
	acpi_size                           length,
	const char                          *caller,
	int                                 line);
#endif

#endif /* _KERNEL */

#endif /* __ACDRAGONFLYEX_H__ */

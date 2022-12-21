/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acdragonfly.h - OS specific for dragon_fly BSD
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACDRAGONFLY_H_
#define __ACDRAGONFLY_H_

#include <sys/types.h>

#ifdef __LP64__
#define ACPI_MACHINE_WIDTH              64
#else
#define ACPI_MACHINE_WIDTH              32
#define ACPI_USE_NATIVE_DIVIDE
#define ACPI_USE_NATIVE_MATH64
#endif

#define acpi_uintptr_t                          uintptr_t
#define COMPILER_DEPENDENT_INT64        int64_t
#define COMPILER_DEPENDENT_UINT64       uint64_t

#define ACPI_USE_DO_WHILE_0
#define ACPI_USE_SYSTEM_CLIBRARY

#ifdef _KERNEL

#include "opt_acpi.h"
#include <sys/ctype.h>
#include <sys/systm.h>
#include <machine/acpica_machdep.h>
#include <stdarg.h>

#ifdef ACPI_DEBUG
#define ACPI_DEBUG_OUTPUT       /* enable debug output */
#ifdef DEBUGGER_THREADING
#undef DEBUGGER_THREADING
#endif /* DEBUGGER_THREADING */
#define DEBUGGER_THREADING DEBUGGER_SINGLE_THREADED /* integrated with DDB */
#include "opt_ddb.h"
#ifdef DDB
#define ACPI_DEBUGGER
#endif /* DDB */
#define ACPI_DISASSEMBLER
#endif

#ifdef ACPI_DEBUG_CACHE
#define ACPI_USE_ALTERNATE_PROTOTYPE_acpi_os_release_object
#define acpi_os_release_object(cache, object) \
	 _acpi_os_release_object((cache), (object), __func__, __LINE__)
#endif

#ifdef ACPI_DEBUG_LOCKS
#define ACPI_USE_ALTERNATE_PROTOTYPE_acpi_os_acquire_lock
#define acpi_os_acquire_lock(handle) \
		_acpi_os_acquire_lock((handle), __func__, __LINE__)
#endif

#ifdef ACPI_DEBUG_MEMMAP
#define ACPI_USE_ALTERNATE_PROTOTYPE_acpi_os_map_memory
#define acpi_os_map_memory(where, length) \
		_acpi_os_map_memory((where), (length), __func__, __LINE__)

#define ACPI_USE_ALTERNATE_PROTOTYPE_acpi_os_unmap_memory
#define acpi_os_unmap_memory(logical_address, size) \
		_acpi_os_unmap_memory((logical_address), (size), __func__, __LINE__)
#endif

/* XXX TBI */
#define ACPI_USE_ALTERNATE_PROTOTYPE_acpi_os_wait_events_complete
#define acpi_os_wait_events_complete()

#define USE_NATIVE_ALLOCATE_ZEROED

#define acpi_spinlock           struct acpi_spinlock *
struct acpi_spinlock;

#define acpi_cache_t            struct acpicache
struct acpicache;

#else /* _KERNEL */

#define ACPI_USE_STANDARD_HEADERS

#define ACPI_CAST_PTHREAD_T(pthread)    ((acpi_thread_id) ACPI_TO_INTEGER (pthread))
#define ACPI_FLUSH_CPU_CACHE()

#endif /* _KERNEL */

#endif /* __ACDRAGONFLY_H_ */

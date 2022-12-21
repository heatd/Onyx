/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acnetbsd.h - OS specific defines, etc.
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACNETBSD_H__
#define __ACNETBSD_H__

#define acpi_uintptr_t                  uintptr_t
#define ACPI_USE_LOCAL_CACHE
#define ACPI_CAST_PTHREAD_T(x)  ((acpi_thread_id) ACPI_TO_INTEGER (x))

#ifdef _LP64
#define ACPI_MACHINE_WIDTH      64
#else
#define ACPI_MACHINE_WIDTH      32
#endif

#define COMPILER_DEPENDENT_INT64  int64_t
#define COMPILER_DEPENDENT_UINT64 uint64_t

#if defined(_KERNEL) || defined(_STANDALONE)
#ifdef _KERNEL_OPT
#include "opt_acpi.h"           /* collect build-time options here */
#endif /* _KERNEL_OPT */

#include <sys/param.h>
#include <sys/systm.h>
#include <machine/stdarg.h>
#include <machine/acpi_func.h>

#define asm         __asm

#define ACPI_USE_NATIVE_DIVIDE
#define ACPI_USE_NATIVE_MATH64

#define ACPI_SYSTEM_XFACE
#define ACPI_EXTERNAL_XFACE
#define ACPI_INTERNAL_XFACE
#define ACPI_INTERNAL_VAR_XFACE

#ifdef ACPI_DEBUG
#define ACPI_DEBUG_OUTPUT
#define ACPI_DBG_TRACK_ALLOCATIONS
#ifdef DEBUGGER_THREADING
#undef DEBUGGER_THREADING
#endif /* DEBUGGER_THREADING */
#define DEBUGGER_THREADING 0    /* integrated with DDB */
#include "opt_ddb.h"
#ifdef DDB
#define ACPI_DISASSEMBLER
#define ACPI_DEBUGGER
#endif /* DDB */
#endif /* ACPI_DEBUG */

#else /* defined(_KERNEL) || defined(_STANDALONE) */

#include <ctype.h>
#include <stdint.h>

/* Not building kernel code, so use libc */
#define ACPI_USE_STANDARD_HEADERS

#define __cli()
#define __sti()
#define __cdecl

#endif /* defined(_KERNEL) || defined(_STANDALONE) */

/* Always use net_BSD code over our local versions */
#define ACPI_USE_SYSTEM_CLIBRARY
#define ACPI_USE_NATIVE_DIVIDE
#define ACPI_USE_NATIVE_MATH64

#endif /* __ACNETBSD_H__ */

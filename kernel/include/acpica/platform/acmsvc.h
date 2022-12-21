/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acmsvc.h - VC specific defines, etc.
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACMSVC_H__
#define __ACMSVC_H__

/* Note: do not include any C library headers here */

/*
 * Note: MSVC project files should define ACPI_DEBUGGER and ACPI_DISASSEMBLER
 * as appropriate to enable editor functions like "Find all references".
 * The editor isn't smart enough to dig through the include files to find
 * out if these are actually defined.
 */

/* Eliminate warnings for "old" (non-secure) versions of clib functions */

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

/* Eliminate warnings for POSIX clib function names (open, write, etc.) */

#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif

#define COMPILER_DEPENDENT_INT64    __int64
#define COMPILER_DEPENDENT_UINT64   unsigned __int64
#define ACPI_INLINE                 __inline

/*
 * Calling conventions:
 *
 * ACPI_SYSTEM_XFACE        - Interfaces to host OS (handlers, threads)
 * ACPI_EXTERNAL_XFACE      - External ACPI interfaces
 * ACPI_INTERNAL_XFACE      - Internal ACPI interfaces
 * ACPI_INTERNAL_VAR_XFACE  - Internal variable-parameter list interfaces
 */
#define ACPI_SYSTEM_XFACE           __cdecl
#define ACPI_EXTERNAL_XFACE
#define ACPI_INTERNAL_XFACE
#define ACPI_INTERNAL_VAR_XFACE     __cdecl


/* Do not maintain the architecture specific stuffs for the EFI ports */

#if defined(__i386__) && !defined(_GNU_EFI) && !defined(_EDK2_EFI)
/*
 * Math helper functions
 */
#ifndef ACPI_DIV_64_BY_32
#define ACPI_DIV_64_BY_32(n_hi, n_lo, d32, q32, r32) \
{                           \
	__asm mov    edx, n_hi  \
	__asm mov    eax, n_lo  \
	__asm div    d32        \
	__asm mov    q32, eax   \
	__asm mov    r32, edx   \
}
#endif

#ifndef ACPI_MUL_64_BY_32
#define ACPI_MUL_64_BY_32(n_hi, n_lo, m32, p32, c32) \
{                           \
	__asm mov    edx, n_hi  \
	__asm mov    eax, n_lo  \
	__asm mul    m32        \
	__asm mov    p32, eax   \
	__asm mov    c32, edx   \
}
#endif

#ifndef ACPI_SHIFT_LEFT_64_BY_32
#define ACPI_SHIFT_LEFT_64_BY_32(n_hi, n_lo, s32) \
{                               \
	__asm mov    edx, n_hi      \
	__asm mov    eax, n_lo      \
	__asm mov    ecx, s32       \
	__asm and    ecx, 31        \
	__asm shld   edx, eax, cl   \
	__asm shl    eax, cl        \
	__asm mov    n_hi, edx      \
	__asm mov    n_lo, eax      \
}
#endif

#ifndef ACPI_SHIFT_RIGHT_64_BY_32
#define ACPI_SHIFT_RIGHT_64_BY_32(n_hi, n_lo, s32) \
{                               \
	__asm mov    edx, n_hi      \
	__asm mov    eax, n_lo      \
	__asm mov    ecx, s32       \
	__asm and    ecx, 31        \
	__asm shrd   eax, edx, cl   \
	__asm shr    edx, cl        \
	__asm mov    n_hi, edx      \
	__asm mov    n_lo, eax      \
}
#endif

#ifndef ACPI_SHIFT_RIGHT_64
#define ACPI_SHIFT_RIGHT_64(n_hi, n_lo) \
{                           \
	__asm shr    n_hi, 1    \
	__asm rcr    n_lo, 1    \
}
#endif
#endif

/* warn C4001: use of slash-slash comments */
/* NOTE: MSVC 2015 headers use these extensively */
#pragma warning(disable:4001)

/* warn C4100: unreferenced formal parameter */
#pragma warning(disable:4100)

/* warn C4127: conditional expression is constant */
#pragma warning(disable:4127)

/* warn C4706: assignment within conditional expression */
#pragma warning(disable:4706)

/* warn C4131: uses old-style declarator (iASL compiler only) */
#pragma warning(disable:4131)

/* warn C4131: uses old-style declarator (iASL compiler only) */
#pragma warning(disable:4459)

/* warn c4200: allow flexible arrays (of zero length) */
#pragma warning(disable:4200)


/*
 * MSVC 2015+
 */

 /* warn C4459: xxxx (identifier) hides global declaration */
#pragma warning(disable:4459)


/* Debug support. */

#ifdef _DEBUG

/*
 * Debugging memory corruption issues with windows:
 * Add #include <crtdbg.h> to accommon.h if necessary.
 * Add _ASSERTE(_crt_check_memory()); where needed to test memory integrity.
 * This can quickly localize the memory corruption.
 */
#define ACPI_DEBUG_INITIALIZE() \
	_crt_set_dbg_flag (\
		_CRTDBG_CHECK_ALWAYS_DF | \
		_CRTDBG_ALLOC_MEM_DF | \
		_CRTDBG_DELAY_FREE_MEM_DF | \
		_CRTDBG_LEAK_CHECK_DF | \
		_crt_set_dbg_flag(_CRTDBG_REPORT_FLAG));

#if 0
/*
 * _crt_set_break_alloc can be used to set a breakpoint at a particular
 * memory leak, add to the macro above.
 */
detected memory leaks!
dumping objects ->
..\..\source\os_specific\service_layers\oswinxf.c(701) : {937} normal block at 0x002E9190, 40 bytes long.
 data: <                > 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

_crt_set_break_alloc (937);
#endif

#endif


/* Begin standard headers */

/*
 * warn C4001: nonstandard extension 'single line comment' was used
 *
 * We need to enable this for ACPICA internal files, but disable it for
 * buggy MS runtime headers.
 */
#pragma warning(push)
#pragma warning(disable:4001)

#endif /* __ACMSVC_H__ */

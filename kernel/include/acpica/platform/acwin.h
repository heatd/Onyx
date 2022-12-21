/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acwin.h - OS specific defines, etc.
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACWIN_H__
#define __ACWIN_H__

#include <io.h>

#define ACPI_USE_STANDARD_HEADERS
#define ACPI_USE_SYSTEM_CLIBRARY

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


#define ACPI_MACHINE_WIDTH      32
#define ACPI_USE_NATIVE_DIVIDE
#define ACPI_USE_NATIVE_MATH64

#ifdef ACPI_DEFINE_ALTERNATE_TYPES
/*
 * Types used only in (Linux) translated source, defined here to enable
 * cross-platform compilation (i.e., generate the Linux code on Windows,
 * for test purposes only)
 */
typedef int                                     s32;
typedef unsigned char                           u8;
typedef unsigned short                  u16;
typedef unsigned int                            u32;
typedef COMPILER_DEPENDENT_UINT64       u64;
#endif

/*
 * Map low I/O functions for MS. This allows us to disable MS language
 * extensions for maximum portability.
 */
#define open            _open
#define read            _read
#define write           _write
#define close           _close
#define stat            _stat
#define fstat           _fstat
#define mkdir           _mkdir
#define fileno          _fileno
#define isatty          _isatty

#define O_RDONLY        _O_RDONLY
#define O_BINARY        _O_BINARY
#define O_CREAT         _O_CREAT
#define O_WRONLY        _O_WRONLY
#define O_TRUNC         _O_TRUNC
#define S_IREAD         _S_IREAD
#define S_IWRITE        _S_IWRITE
#define S_IFDIR         _S_IFDIR


/*
 * Handle platform- and compiler-specific assembly language differences.
 *
 * Notes:
 * 1) Interrupt 3 is used to break into a debugger
 * 2) Interrupts are turned off during ACPI register setup
 */

/*! [Begin] no source code translation  */

#ifdef ACPI_APPLICATION
#define ACPI_FLUSH_CPU_CACHE()
#else
#define ACPI_FLUSH_CPU_CACHE()  __asm {WBINVD}
#endif

#ifdef _DEBUG
#define ACPI_SIMPLE_RETURN_MACROS
#endif

/*! [End] no source code translation !*/

/*
 * Global Lock acquire/release code
 *
 * Note: Handles case where the FACS pointer is null
 */
#define ACPI_ACQUIRE_GLOBAL_LOCK(facs_ptr, acq) __asm \
{                                                   \
	 __asm mov           eax, 0xFF               \
	 __asm mov           ecx, facs_ptr           \
	 __asm or            ecx, ecx                \
	 __asm jz            exit_acq                \
	 __asm lea           ecx, [ecx].global_lock  \
			 \
		__asm acq10:                                \
		__asm mov           eax, [ecx]              \
		__asm mov           edx, eax                \
		__asm and           edx, 0xFFFFFFFE         \
		__asm bts           edx, 1                  \
		__asm adc           edx, 0                  \
		__asm lock cmpxchg  dword ptr [ecx], edx    \
		__asm jnz           acq10                   \
				   \
		__asm cmp           dl, 3                   \
		__asm sbb           eax, eax                \
				   \
		__asm exit_acq:                             \
		__asm mov           acq, al                 \
}

#define ACPI_RELEASE_GLOBAL_LOCK(facs_ptr, pnd) __asm \
{                                                   \
		__asm xor           eax, eax                \
		__asm mov           ecx, facs_ptr           \
		__asm or            ecx, ecx                \
		__asm jz            exit_rel                \
		__asm lea           ecx, [ecx].global_lock  \
				   \
		__asm rel10:                                \
		__asm mov           eax, [ecx]              \
		__asm mov           edx, eax                \
		__asm and           edx, 0xFFFFFFFC         \
		__asm lock cmpxchg  dword ptr [ecx], edx    \
		__asm jnz           rel10                   \
				   \
		__asm cmp           dl, 3                   \
		__asm and           eax, 1                  \
				   \
		__asm exit_rel:                             \
		__asm mov           pnd, al                 \
}

#endif /* __ACWIN_H__ */

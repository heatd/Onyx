/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acwin64.h - OS specific defines, etc.
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACWIN64_H__
#define __ACWIN64_H__

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


#define ACPI_MACHINE_WIDTH          64

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
#define snprintf        _snprintf
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

#define ACPI_FLUSH_CPU_CACHE()

/*
 * For Acpi applications, we don't want to try to access the global lock
 */
#ifdef ACPI_APPLICATION
#define ACPI_ACQUIRE_GLOBAL_LOCK(GLptr, Acq)       if (AcpiGbl_GlobalLockPresent) {Acq = 0xFF;} else {Acq = 0;}
#define ACPI_RELEASE_GLOBAL_LOCK(GLptr, Pnd)       if (AcpiGbl_GlobalLockPresent) {Pnd = 0xFF;} else {Pnd = 0;}
#else

#define ACPI_ACQUIRE_GLOBAL_LOCK(GLptr, Acq)

#define ACPI_RELEASE_GLOBAL_LOCK(GLptr, Pnd)

#endif

/*! [End] no source code translation !*/

#endif /* __ACWIN_H__ */

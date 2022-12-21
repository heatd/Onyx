/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acefi.h - OS specific defines, etc.
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACEFI_H__
#define __ACEFI_H__

/*
 * Single threaded environment where Mutex/Event/Sleep are fake. This model is
 * sufficient for pre-boot acpi_exec.
 */
#ifndef DEBUGGER_THREADING
#define DEBUGGER_THREADING          DEBUGGER_SINGLE_THREADED
#endif /* !DEBUGGER_THREADING */

/* EDK2 EFI environment */

#if defined(_EDK2_EFI)

#ifdef USE_STDLIB
#define ACPI_USE_STANDARD_HEADERS
#define ACPI_USE_SYSTEM_CLIBRARY
#define ACPI_USE_NATIVE_DIVIDE
#define ACPI_USE_NATIVE_MATH64
#endif

#endif

#if defined(__x86_64__)
#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 7))
#define USE_MS_ABI 1
#endif
#endif

#ifdef _MSC_EXTENSIONS
#define ACPI_EFI_API __cdecl
#elif USE_MS_ABI
#define ACPI_EFI_API __attribute__((ms_abi))
#else
#define ACPI_EFI_API
#endif

#define VOID        void

#if defined(__ia64__) || defined(__x86_64__)

#define ACPI_MACHINE_WIDTH          64

#if defined(__x86_64__)

/* for x86_64, EFI_FUNCTION_WRAPPER must be defined */

#ifndef USE_MS_ABI
#define USE_EFI_FUNCTION_WRAPPER
#endif

#ifdef _MSC_EXTENSIONS
#pragma warning ( disable : 4731 )  /* Suppress warnings about modification of EBP */
#endif

#endif

#ifndef USE_STDLIB
#define UINTN       uint64_t
#define INTN        int64_t
#endif

#define ACPI_EFI_ERR(a)             (0x8000000000000000 | a)

#else

#define ACPI_MACHINE_WIDTH          32

#ifndef USE_STDLIB
#define UINTN       uint32_t
#define INTN        int32_t
#endif

#define ACPI_EFI_ERR(a)             (0x80000000 | a)

#endif

#define CHAR16      uint16_t

#ifdef USE_EFI_FUNCTION_WRAPPER
#define __VA_NARG__(...)                        \
  __VA_NARG_(_0, ## __VA_ARGS__, __RSEQ_N())
#define __VA_NARG_(...)                         \
  __VA_ARG_N(__VA_ARGS__)
#define __VA_ARG_N(                             \
  _0,_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,N,...) N
#define __RSEQ_N()                              \
  10, 9,  8,  7,  6,  5,  4,  3,  2,  1,  0

#define __VA_ARG_NSUFFIX__(prefix,...)                  \
  __VA_ARG_NSUFFIX_N(prefix, __VA_NARG__(__VA_ARGS__))
#define __VA_ARG_NSUFFIX_N(prefix,nargs)        \
  __VA_ARG_NSUFFIX_N_(prefix, nargs)
#define __VA_ARG_NSUFFIX_N_(prefix,nargs)       \
  prefix ## nargs

/* Prototypes of EFI cdecl -> stdcall trampolines */

u64 efi_call0(void *func);
u64 efi_call1(void *func, u64 arg1);
u64 efi_call2(void *func, u64 arg1, u64 arg2);
u64 efi_call3(void *func, u64 arg1, u64 arg2, u64 arg3);
u64 efi_call4(void *func, u64 arg1, u64 arg2, u64 arg3,
	 u64 arg4);
u64 efi_call5(void *func, u64 arg1, u64 arg2, u64 arg3,
			  u64 arg4, u64 arg5);
u64 efi_call6(void *func, u64 arg1, u64 arg2, u64 arg3,
				 u64 arg4, u64 arg5, u64 arg6);
u64 efi_call7(void *func, u64 arg1, u64 arg2, u64 arg3,
				 u64 arg4, u64 arg5, u64 arg6, u64 arg7);
u64 efi_call8(void *func, u64 arg1, u64 arg2, u64 arg3,
				 u64 arg4, u64 arg5, u64 arg6, u64 arg7,
				 u64 arg8);
u64 efi_call9(void *func, u64 arg1, u64 arg2, u64 arg3,
				 u64 arg4, u64 arg5, u64 arg6, u64 arg7,
				 u64 arg8, u64 arg9);
u64 efi_call10(void *func, u64 arg1, u64 arg2, u64 arg3,
				  u64 arg4, u64 arg5, u64 arg6, u64 arg7,
				  u64 arg8, u64 arg9, u64 arg10);

/* Front-ends to efi_callX to avoid compiler warnings */

#define _cast64_efi_call0(f) \
  efi_call0(f)
#define _cast64_efi_call1(f,a1) \
  efi_call1(f, (u64)(a1))
#define _cast64_efi_call2(f,a1,a2) \
  efi_call2(f, (u64)(a1), (u64)(a2))
#define _cast64_efi_call3(f,a1,a2,a3) \
  efi_call3(f, (u64)(a1), (u64)(a2), (u64)(a3))
#define _cast64_efi_call4(f,a1,a2,a3,a4) \
  efi_call4(f, (u64)(a1), (u64)(a2), (u64)(a3), (u64)(a4))
#define _cast64_efi_call5(f,a1,a2,a3,a4,a5) \
  efi_call5(f, (u64)(a1), (u64)(a2), (u64)(a3), (u64)(a4), \
			(u64)(a5))
#define _cast64_efi_call6(f,a1,a2,a3,a4,a5,a6) \
  efi_call6(f, (u64)(a1), (u64)(a2), (u64)(a3), (u64)(a4), \
			(u64)(a5), (u64)(a6))
#define _cast64_efi_call7(f,a1,a2,a3,a4,a5,a6,a7) \
  efi_call7(f, (u64)(a1), (u64)(a2), (u64)(a3), (u64)(a4), \
			(u64)(a5), (u64)(a6), (u64)(a7))
#define _cast64_efi_call8(f,a1,a2,a3,a4,a5,a6,a7,a8) \
  efi_call8(f, (u64)(a1), (u64)(a2), (u64)(a3), (u64)(a4), \
			(u64)(a5), (u64)(a6), (u64)(a7), (u64)(a8))
#define _cast64_efi_call9(f,a1,a2,a3,a4,a5,a6,a7,a8,a9) \
  efi_call9(f, (u64)(a1), (u64)(a2), (u64)(a3), (u64)(a4), \
			(u64)(a5), (u64)(a6), (u64)(a7), (u64)(a8), \
			(u64)(a9))
#define _cast64_efi_call10(f,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10) \
  efi_call10(f, (u64)(a1), (u64)(a2), (u64)(a3), (u64)(a4), \
			 (u64)(a5), (u64)(a6), (u64)(a7), (u64)(a8), \
			 (u64)(a9), (u64)(a10))

/* main wrapper (va_num ignored) */

#define uefi_call_wrapper(func,va_num,...)                        \
  __VA_ARG_NSUFFIX__(_cast64_efi_call, __VA_ARGS__) (func , ##__VA_ARGS__)

#else

#define uefi_call_wrapper(func, va_num, ...) func(__VA_ARGS__)

#endif

/* AED EFI definitions */

#if defined(_AED_EFI)

/* _int64 works for both IA32 and IA64 */

#define COMPILER_DEPENDENT_INT64   __int64
#define COMPILER_DEPENDENT_UINT64  unsigned __int64

/*
 * Calling conventions:
 *
 * ACPI_SYSTEM_XFACE        - Interfaces to host OS (handlers, threads)
 * ACPI_EXTERNAL_XFACE      - External ACPI interfaces
 * ACPI_INTERNAL_XFACE      - Internal ACPI interfaces
 * ACPI_INTERNAL_VAR_XFACE  - Internal variable-parameter list interfaces
 */
#define ACPI_SYSTEM_XFACE
#define ACPI_EXTERNAL_XFACE
#define ACPI_INTERNAL_XFACE
#define ACPI_INTERNAL_VAR_XFACE

/* warn C4142: redefinition of type */

#pragma warning(disable:4142)

#endif


/* EFI math64 definitions */

#if defined(_GNU_EFI) || defined(_EDK2_EFI)
/*
 * Math helpers, GNU EFI provided a platform independent 64-bit math
 * support.
 */
#ifndef ACPI_DIV_64_BY_32
#define ACPI_DIV_64_BY_32(n_hi, n_lo, d32, q32, r32)         \
	do {                                                     \
		u64 __n = ((u64) n_hi) << 32 | (n_lo);         \
		(q32) = (u32) div_u64x32 ((__n), (d32), &(r32));  \
	} while (0)
#endif

#ifndef ACPI_MUL_64_BY_32
#define ACPI_MUL_64_BY_32(n_hi, n_lo, m32, p32, c32) \
	do {                                             \
		u64 __n = ((u64) n_hi) << 32 | (n_lo); \
		u64 __p = mult_u64x32 (__n, (m32));       \
		(p32) = (u32) __p;                        \
		(c32) = (u32) (__p >> 32);                \
	} while (0)
#endif

#ifndef ACPI_SHIFT_LEFT_64_by_32
#define ACPI_SHIFT_LEFT_64_BY_32(n_hi, n_lo, s32)    \
	do {                                             \
		u64 __n = ((u64) n_hi) << 32 | (n_lo); \
		u64 __r = lshift_u64 (__n, (s32));        \
		(n_lo) = (u32) __r;                       \
		(n_hi) = (u32) (__r >> 32);               \
	} while (0)
#endif

#ifndef ACPI_SHIFT_RIGHT_64_BY_32
#define ACPI_SHIFT_RIGHT_64_BY_32(n_hi, n_lo, s32)   \
	do {                                             \
		u64 __n = ((u64) n_hi) << 32 | (n_lo); \
		u64 __r = rshift_u64 (__n, (s32));        \
		(n_lo) = (u32) __r;                       \
		(n_hi) = (u32) (__r >> 32);               \
	} while (0)
#endif

#ifndef ACPI_SHIFT_RIGHT_64
#define ACPI_SHIFT_RIGHT_64(n_hi, n_lo) \
	do {                                \
		(n_lo) >>= 1;                   \
		(n_lo) |= (((n_hi) & 1) << 31); \
		(n_hi) >>= 1;                   \
	} while (0)
#endif
#endif

struct _ACPI_SIMPLE_TEXT_OUTPUT_INTERFACE;
struct _ACPI_SIMPLE_INPUT_INTERFACE;
struct _ACPI_EFI_FILE_IO_INTERFACE;
struct _ACPI_EFI_FILE_HANDLE;
struct _ACPI_EFI_BOOT_SERVICES;
struct _ACPI_EFI_RUNTIME_SERVICES;
struct _ACPI_EFI_SYSTEM_TABLE;
struct _ACPI_EFI_PCI_IO;

extern struct _ACPI_EFI_SYSTEM_TABLE        *ST;
extern struct _ACPI_EFI_BOOT_SERVICES       *BS;
extern struct _ACPI_EFI_RUNTIME_SERVICES    *RT;

#ifndef USE_STDLIB
typedef union acpi_efi_file acpi_efi_file;
#define FILE                        acpi_efi_file

extern FILE                         *stdin;
extern FILE                         *stdout;
extern FILE                         *stderr;
#endif

#endif /* __ACEFI_H__ */

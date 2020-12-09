/******************************************************************************
 *
 * Name: aconyx.h - OS specific defines, etc. for Onyx
 *
 *****************************************************************************/

#ifndef _ACONYX_
#define _ACONYX_
#include <stdint.h>
#include <stdarg.h>

// TODO: Handle this being different
#define ACPI_MACHINE_WIDTH	64

#define COMPILER_DEPENDENT_INT64        int64_t
#define COMPILER_DEPENDENT_UINT64       uint64_t

#define ACPI_UINTPTR_T      uintptr_t

#define ACPI_USE_DO_WHILE_0

#undef ACPI_APPLICATION
#undef ACPI_DEBUGGER
#undef ACPI_DISASSEMBLER

struct mutex;
struct semaphore;
struct spinlock;

#define ACPI_MUTEX_TYPE             ACPI_OSL_MUTEX
#define ACPI_MUTEX                  struct mutex *
#define ACPI_SPINLOCK 				struct spinlock*
#define ACPI_SEMAPHORE              struct semaphore*

#define ACPI_USE_SYSTEM_CLIBRARY
#undef ACPI_USE_STANDARD_HEADERS

#include <ctype.h>
#include <string.h>
//#undef ACPI_USE_LOCAL_CACHE
//#undef ACPI_USE_NATIVE_DIVIDE

#include "acgcc.h"

#endif

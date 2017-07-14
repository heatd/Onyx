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

#define ACPI_MUTEX_TYPE             ACPI_OSL_MUTEX
#define ACPI_MUTEX                  unsigned long*
#undef ACPI_USE_SYSTEM_CLIBRARY
#undef ACPI_USE_STANDARD_HEADERS
//#undef ACPI_USE_NATIVE_DIVIDE

#include "acgcc.h"

#endif

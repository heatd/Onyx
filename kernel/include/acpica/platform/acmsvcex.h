/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acmsvcex.h - Extra VC specific defines, etc.
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACMSVCEX_H__
#define __ACMSVCEX_H__

/* va_arg implementation can be compiler specific */

#ifdef ACPI_USE_STANDARD_HEADERS

#include <stdarg.h>

#endif /* ACPI_USE_STANDARD_HEADERS */

/* Debug support. */

#ifdef _DEBUG
#define _CRTDBG_MAP_ALLOC /* Enables specific file/lineno for leaks */
#include <crtdbg.h>
#endif

/* End standard headers */

#pragma warning(pop)

#ifndef ACPI_USE_SYSTEM_CLIBRARY

/******************************************************************************
 *
 * Not using native C library, use local implementations
 *
 *****************************************************************************/

#ifndef va_arg

#ifndef _VALIST
#define _VALIST
typedef char *va_list;
#endif /* _VALIST */

/* Storage alignment properties */

#define  _AUPBND                (sizeof (acpi_native_int) - 1)
#define  _ADNBND                (sizeof (acpi_native_int) - 1)

/* Variable argument list macro definitions */

#define _bnd(X, bnd)            (((sizeof (X)) + (bnd)) & (~(bnd)))
#define va_arg(ap, T)           (*(T *)(((ap) += (_bnd (T, _AUPBND))) - (_bnd (T,_ADNBND))))
#define va_end(ap)              (ap = (va_list) NULL)
#define va_start(ap, A)         (void) ((ap) = (((char *) &(A)) + (_bnd (A,_AUPBND))))

#endif /* va_arg */

#endif /* !ACPI_USE_SYSTEM_CLIBRARY */

#endif /* __ACMSVCEX_H__ */

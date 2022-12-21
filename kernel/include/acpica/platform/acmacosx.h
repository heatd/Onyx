/* SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0 */
/******************************************************************************
 *
 * Name: acmacosx.h - OS specific defines, etc. for Mac OS X
 *
 * Copyright (C) 2000 - 2022, Intel Corp.
 *
 *****************************************************************************/


#ifndef __ACMACOSX_H__
#define __ACMACOSX_H__

#include "aclinux.h"

#ifdef __APPLE__
#define ACPI_USE_ALTERNATE_TIMEOUT
#endif /* __APPLE__ */

#ifdef __clang__
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif

#endif /* __ACMACOSX_H__ */

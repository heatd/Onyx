/*
 * Copyright (c) 2021 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_HANDLE_H
#define _UAPI_HANDLE_H

#define ONX_HANDLE_TYPE_PROCESS 0

#define ONX_HANDLE_CLOEXEC (1 << 0)

#define ONX_HANDLE_OPEN_GENERIC_FLAGS (ONX_HANDLE_CLOEXEC)

#endif

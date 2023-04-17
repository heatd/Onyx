/*
 * Copyright (c) 2020 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _UAPI_POWER_MANAGEMENT_H
#define _UAPI_POWER_MANAGEMENT_H

#define POWER_STATE_REBOOT   0
#define POWER_STATE_SHUTDOWN 1
#define POWER_STATE_HALT     2
#define POWER_STATE_SUSPEND  3

#define POWER_STATE_FLAG_NO_SYNC (1 << 0)

#endif

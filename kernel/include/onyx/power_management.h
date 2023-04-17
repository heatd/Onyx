/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_POWER_MANAGEMENT_H
#define _ONYX_POWER_MANAGEMENT_H

#include <uapi/power_management.h>

int set_power_state(unsigned int state, unsigned int flags);

#endif

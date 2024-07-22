/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _PIT_H
#define _PIT_H

#include <stdint.h>

void pit_init_oneshot(uint32_t hz);
void pit_wait_for_oneshot(void);
uint16_t __pit_get_counter(void);
void pit_stop(void);

#endif

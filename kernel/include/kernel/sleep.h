/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_SLEEP_H
#define _KERNEL_SLEEP_H
#include <stdint.h>
#include <kernel/timer.h>

void ksleep(uint32_t ms);
#endif

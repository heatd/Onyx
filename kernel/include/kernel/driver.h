/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_DRIVER_H
#define _KERNEL_DRIVER_H

#include <kernel/module.h>

#define DRIVER_INIT(x) __attribute__((section(".driver.init"), used, aligned(1))) \
static void(*__module_init)(void) = x

void driver_init(void);

#endif

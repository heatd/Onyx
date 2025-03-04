/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _KERNEL_DRIVER_H
#define _KERNEL_DRIVER_H

#define DRIVER_INIT(x) \
    __attribute__((section(".driver.init"), used)) static int (*__module_init)(void) = x

#include <onyx/module.h>

void driver_init(void);

#endif

/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_INFO_H
#define _KERNEL_INFO_H

#include <onyx/utils.h>

#define OS_NAME "Onyx"
#define OS_TAGLINE "hey it's me, your unix"
#define OS_RELEASE "onyx-rolling"
#define OS_VERSION "SMP " __DATE__ " " __TIME__

#if defined(__x86_64__)
#define OS_MACHINE "x86_64 amd64"
#elif defined(__riscv)
#define OS_MACHINE "riscv64"
#else
#error "Define a machine string for your architecture"
#endif

#endif

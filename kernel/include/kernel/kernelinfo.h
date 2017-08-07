/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_INFO_H
#define _KERNEL_INFO_H

#undef stringify
#define stringify(str) #str
#define OS_NAME "Onyx"
#define OS_TAGLINE "hey it's me, your unix"
#define OS_RELEASE "0.4"
#define OS_VERSION "SMP "__DATE__" "__TIME__

#if defined(__x86_64__)
#define OS_MACHINE "x86_64 amd64"
#else
#error "Define a machine string for your architecture"
#endif

#endif

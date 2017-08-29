/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _VMLAYOUT_KERNEL_H
#define _VMLAYOUT_KERNEL_H

#ifdef __x86_64__
#include <kernel/x86/vm_layout.h>
#else
#error "No vm layout provided for the current architecture"
#endif

#endif

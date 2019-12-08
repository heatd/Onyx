/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_X86_MCE_H
#define _ONYX_X86_MCE_H

#include <onyx/registers.h>

void do_machine_check(struct registers *ctx);

#endif

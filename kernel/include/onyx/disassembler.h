/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_DISASSEMBLER_H
#define _ONYX_DISASSEMBLER_H

#include <stdint.h>

#include <onyx/registers.h>

int debug_opcode(uint8_t *pc, struct registers *ctx);

#endif

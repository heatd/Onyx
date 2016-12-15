/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _KERNEL_CRC32_H
#define _KERNEL_CRC32_H

#include <stdint.h>
#include <stddef.h>

uint32_t crc32_calculate(uint8_t *ptr, size_t len);
uint32_t crc32_calculate_eth(uint8_t *ptr, size_t len);
#endif

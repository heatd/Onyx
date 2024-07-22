/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#ifndef _KERNEL_CRC32_H
#define _KERNEL_CRC32_H

#include <stddef.h>
#include <stdint.h>

uint32_t crc32_calculate(uint8_t *ptr, size_t len);
uint32_t crc32_calculate_eth(uint8_t *ptr, size_t len);

#endif

/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _DRIVERS_MMIO_UTILS_H
#define _DRIVERS_MMIO_UTILS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
uint8_t mmio_readb(uint64_t address);
uint16_t mmio_readw(uint64_t address);
uint32_t mmio_readl(uint64_t address);
uint64_t mmio_readq(uint64_t address);

void mmio_writeb(uint64_t address, uint8_t val);
void mmio_writew(uint64_t address, uint16_t val);
void mmio_writel(uint64_t address, uint32_t val);
void mmio_writeq(uint64_t address, uint64_t val);
#ifdef __cplusplus
}
#endif
#endif

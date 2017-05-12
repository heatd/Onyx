/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <drivers/mmio.h>

uint8_t mmio_readb(uint64_t address)
{
	return *((volatile uint8_t*)(address));
}
uint16_t mmio_readw(uint64_t address)
{
	return *((volatile uint16_t*)(address));
}
uint32_t mmio_readl(uint64_t address)
{
	return *((volatile uint32_t*)(address));
}
uint64_t mmio_readq(uint64_t address)
{
	return *((volatile uint64_t*)(address));
}
void mmio_writeb(uint64_t address, uint8_t val)
{
	(*((volatile uint8_t*)(address)))=(val);
}
void mmio_writew(uint64_t address, uint16_t val)
{
	(*((volatile uint16_t*)(address)))=(val);
}
void mmio_writel(uint64_t address, uint32_t val)
{
	(*((volatile uint32_t*)(address)))=(val);
}
void mmio_writeq(uint64_t address, uint64_t val)
{
	(*((volatile uint64_t*)(address)))=(val);
}
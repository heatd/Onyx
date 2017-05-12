/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _PORTIO_KERNEL_H
#define _PORTIO_KERNEL_H
#include <stdlib.h>
#include <stdint.h>

static inline void outb(uint16_t port,uint8_t val)
{
	__asm__ __volatile__ ("outb %0, %1" : : "a"(val), "Nd"(port));
}
static inline void outw(uint16_t port,uint16_t val)
{
	__asm__ __volatile__ ("outw %0, %1" : : "a"(val), "Nd"(port));
}
static inline void outl(uint16_t port,uint32_t val)
{
	__asm__ __volatile__ ("outl %0, %1" : : "a"(val), "Nd"(port));
}
static inline uint8_t inb(uint16_t port)
{
	uint8_t ret;
	__asm__ __volatile__ ( "inb %1, %0" : "=a"(ret) : "Nd"(port) );
	return ret;
}
static inline uint16_t inw(uint16_t port)
{
	uint16_t ret;
	__asm__ __volatile__ ( "inw %1, %0" : "=a"(ret) : "Nd"(port) );
	return ret;
}
static inline uint32_t inl(uint16_t port)
{
	uint32_t ret;
	__asm__ __volatile__ ( "inl %1, %0" : "=a"(ret) : "Nd"(port) );
	return ret;
}
static inline void io_wait(void)
{
        /* Port 0x80 is used for 'checkpoints' during POST. */
        /* The Linux kernel seems to think it is free for use :-/ */
        __asm__ __volatile__ ( "outb %%al, $0x80" : : "a"(0) );
}
#endif

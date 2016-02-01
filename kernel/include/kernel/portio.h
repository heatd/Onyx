/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef PORTIO_H
#define PORTIO_H
#include <stdlib.h>


static inline void outb(uint16_t port,uint8_t val)
{
	asm volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}
static inline void outw(uint16_t port,uint16_t val)
{
	asm volatile ("outw %0, %1" : : "a"(val), "Nd"(port));
}
static inline void outl(uint16_t port,uint32_t val)
{
	asm volatile ("outl %0, %1" : : "a"(val), "Nd"(port));
}
static inline uint8_t inb(uint16_t port)
{
	uint8_t ret;
	asm volatile ( "inb %1, %0" : "=a"(ret) : "Nd"(port) );
	return ret;
}
static inline uint16_t inw(uint16_t port)
{
	uint16_t ret;
	asm volatile ( "inw %1, %0" : "=a"(ret) : "Nd"(port) );
	return ret;
}
static inline uint32_t inl(uint16_t port)
{
	uint32_t ret;
	asm volatile ( "inl %1, %0" : "=a"(ret) : "Nd"(port) );
	return ret;
}
static inline void io_wait(void)
{
    /* Port 0x80 is used for 'checkpoints' during POST. */
    /* The Linux kernel seems to think it is free for use :-/ */
    asm volatile ( "outb %%al, $0x80" : : "a"(0) );
}
#endif

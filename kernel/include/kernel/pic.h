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
#ifndef _PIC_H
#define _PIC_H
#include <stdint.h>
#define PIC1		0x20		/* IO base address for master PIC */
#define PIC2		0xA0		/* IO base address for slave PIC */
#define PIC1_COMMAND	PIC1
#define PIC1_DATA	(PIC1+1)
#define PIC2_COMMAND	PIC2
#define PIC2_DATA	(PIC2+1)
#define PIC_READ_IRR	0x0a
#define PIC_READ_ISR	0x0b
#define PIC_EOI		0x20		/* End-of-interrupt command code */
namespace PIC
{
void Disable();
void Remap();
void UnmaskIRQ(uint16_t irqn);
void MaskIRQ(uint16_t irqn);
void SendEOI(unsigned char irqn);
uint16_t GetIRR();
uint16_t GetISR();
}
#endif

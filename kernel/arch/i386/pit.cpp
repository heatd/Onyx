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
/**************************************************************************
 * 
 * 
 * File: pit.c
 * 
 * Description: Contains the PIT code
 * 
 * Date: 2/2/2016
 * 
 * 
 **************************************************************************/
#include <kernel/irq.h>
#include <kernel/portio.h>
#include <kernel/pit.h>
#include <kernel/pic.h>
#include <stdint.h>
#include <kernel/compiler.h>
#include <stdio.h>
#include <kernel/scheduler.h>
static uint64_t timer_ticks = NULL;
extern void halt();
static uint64_t scheduler_last_time;
extern bool is_yielding;
extern "C" void timer_handler()
{
	if(is_yielding == true){
		is_yielding = false;
		return;
	}
	else
		timer_ticks++;
}
namespace PIT
{
void Init(uint32_t frequency)
{
	int divisor = 1193180 / frequency;
	
	outb(0x43, 0x36);
	io_wait();
	outb(0x40, divisor & 0xFF);   // Set low byte of divisor
	io_wait();
	outb(0x40, divisor >> 8);     // Set high byte of divisor
	io_wait();
	PIC::UnmaskIRQ(0); // Unmask IRQ0 (PIT)
	
	irq_t handler = &timer_handler;
	// Install the IRQ handler
	IRQ::InstallHandler(0,handler);
}

uint64_t GetTickCount()
{
	return timer_ticks;
}
};

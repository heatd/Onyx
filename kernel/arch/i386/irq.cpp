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
 * File: irq.c
 * 
 * Description: Contains irq instalation functions
 * 
 * Date: 1/2/2016
 * 
 * 
 **************************************************************************/

#include <kernel/pic.h>
#include <kernel/irq.h>
#include <stdlib.h>
irq_t irq_routines[16]  =
{
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
};

void irq_install_handler(int irq, irq_t handler)
{
	irq_routines[irq] = handler;
}
void irq_uninstall_handler(int irq)
{
	irq_routines[irq] = NULL;
}
extern "C" void irq_handler(uint32_t irqn)
{
	
	irq_t handler = irq_routines[irqn - 32];
	if(handler)
		handler();
	
	pic_send_eoi(irqn - 32);
}
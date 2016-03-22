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
#include <stdlib.h>
#include <stdio.h>
#include <kernel/isr.h>
#include <kernel/panic.h>
#include <kernel/sbrk.h>
static uint32_t faulting_address;
void isr_handler(uint32_t ds, uint32_t int_no, uint32_t err_code)
{
	(void)ds;
	switch (int_no) {
	case 0:{
			panic("Division by zero exception!");
			break;
		}
	case 1:{
			panic("Debug Trap!");
			break;
		}
	case 2:{
			break;
		}
	case 3:{
			printf("Hit a breakpoint");
			break;
		}
	case 4:{
			printf("Overflow trap");
			break;
		}
	case 5:{
			printf("Fault: Bound range exceeded");
			break;
		}
	case 6:{
			panic
			    ("Invalid Instruction.");
			break;
		}
	case 7:{
			printf("Device not available");
			break;
		}
	case 8:{
			panic("Double fault!The kernel is exiting shortly.");
			break;
		}
	case 9:{
			break;	//Obsolete
		}
	case 10:{
			panic("Invalid TSS");
			break;
		}
	case 11:{
			panic("Segment not present!");
			break;
		}
	case 12:{
			panic("Stack segment fault!");
			break;
		}
	case 13:{
			printf("General Protection Fault");
			if (err_code != 0)
				printf("\nSegment 0x%X\n", err_code);
			panic("GPF");
			break;
		}
	case 14:{
			// A page fault has occurred.
			// The faulting address is stored in the CR2 register.
			asm volatile ("mov %%cr2, %0":"=r"
				      (faulting_address));
			if (err_code & 0x2) {
				if (vmm_alloc_cow
				    (faulting_address & 0xFFFFF000) == 1)
					abort();
				return;
			}
		}
	case 15:{
			break;	//Reserved exception
		}
	case 16:{
			printf("x87 floating point exception!");
			break;
		}
	case 17:{
			break;
		}
	case 18:{
			break;
		}
	case 19:{
			printf("SIMD Floating-point exception");
			break;
		}
	case 20:{
			printf("Virtualization exception!");
			break;
		}
	case 21:		/*Handle the intel reserved exceptions to do nothing */
	case 22:
	case 23:
	case 24:
	case 25:
	case 26:
	case 27:
	case 28:
	case 29:
	case 30:
	case 31:
		break;
	}
}

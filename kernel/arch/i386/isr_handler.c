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
static uint32_t faulting_address;
void isr_handler(uint32_t int_no)
{
    switch(int_no)
    {
	case 0: {
		printf("Division by zero exception!");
		break;
	}
	case 1: {
		printf("Debug Trap!");
		break;
	}
	case 2: {
		break;
	}
	case 3: {
		printf("Hit a breakpoint");
		break;
	}
	case 4: {
		printf("Overflow trap");
		break;
	}
	case 5: {
		printf("Fault: Bound range exceeded");
		break;
	}
	case 6: {
		puts("Opcode invalid.The kernel image might be damaged or is running in an unknown or incompatible architecture");
		break;
	}
	case 7: {
		printf("Device not available");
		break;
		}
	case 8: {
		printf("Double fault!The kernel is exiting shortly.");
		break;
		}
	case 9:{
		break;//Obsolete
		}
	case 10: {
		printf("Invalid TSS !!!");
		break;
		}
	case 11: {
		printf("Segment not present!");
		break;
		}
	case 12: {
		puts("Stack segment fault!");
		break;
		}
	case 13: {
		puts("General Protection Fault");
		break;
		}
	case 14:
		// A page fault has occurred.
		// The faulting address is stored in the CR2 register.
		__asm volatile("mov %%cr2, %0" : "=r" (faulting_address));

		// Output an error message.

		printf("Page fault at 0x%x\n",(unsigned int)faulting_address);
		printf("Details: ");
// 		if((regs.err_code >> 1) & 1)
// 			printf("Present,");
// 
// 		if((regs.err_code >> 2) & 1)
// 			printf(" write-access caused the fault,");
// 		else
// 			printf(" read-access caused the fault,");
// 
// 		if((regs.err_code >> 3) & 1)
// 			printf("user mode");
// 		else
// 			printf("kernel-mode\n");

		int i =(int) __builtin_frame_address(1);
		if(i==0)
			printf("0x%x",(unsigned int)__builtin_return_address(1));
		i = (int) __builtin_frame_address(2);
		if(i==0)
			printf("0x%x",(unsigned int)__builtin_return_address(2));
		//mmap(faulting_address, 1);
		break;
	case 15: {
		break;//Reserved exception
		}
	case 16: {
		printf("x87 floating point exception!");
		break;
		}
	case 17: {
		break;
		}
	case 18: {
		break;
		}
	case 19: {
		printf("SIMD Floating-point exception");
		break;
		}
	case 20: {
		printf("Virtualization exception!");
		break;
		}
	case 21:/*Handle the intel reserved exceptions to do nothing */
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

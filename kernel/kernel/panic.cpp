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
#include <stdio.h>
#include <kernel/registers.h>
#include <kernel/compiler.h>
#include <kernel/panic.h>
/**************************************************************************
 * 
 * 
 * File: panic.c
 * 
 * Description: Contains the implementation of the panic function
 * 
 * Date: 1/2/2016
 * 
 * 
 **************************************************************************/
const char* skull = " _,,,,,,,_\n\
          ,88888888888,\n\
        ,888\'       \`888,\n\
        888\' 0     0 \`888\n\
       888      0      888\n\
       888             888\n\
       888    ,000,    888\n\
        888, 0     0 ,888\n\
        \'888,       ,888\'\n\
          \'8JGS8888888\'\n\
            \\`\\`\\`\\`\\`\\`\\`\\`\n";
__attribute__ ((noreturn,cold,noinline))
void panic(const char* msg)
{
	printf("%s",skull);
	printf("panic: %s\n",msg);
	registers_t ctx;
	get_thread_ctx(&ctx);
	printf("Thread context: \n");
#ifdef __x86_64__
	ctx.rip =(uint64_t)__builtin_return_address(0);

	
	printf("rax: %i\nrbx: %i\nrcx: %i\nrdx: %i\nrdi: %i\nrsi: %i\nrbp: 0x%x\nrsp: 0x%x\nrip: 00%x:0x%x\nss:  00%x\nrflags:%i\n",	ctx.rax,ctx.rbx,ctx.rcx,ctx.rdx,ctx.rdi,ctx.rsi,ctx.rbp,ctx.rsp,ctx.cs,ctx.rip,ctx.ss);
	
	printf("Stack dump: \n");
	void* ret_addr = __builtin_frame_address(0);
	printf("#0 stack frame:0x%x\n",(uint64_t)ret_addr);
#elifdef __i386__
	ctx.eip =(uint32_t)__builtin_return_address(0);
	printf("eax: %i\nebx: %i\necx: %i\nedx: %i\nedi: %i\nesi: %i\nebp: 0x%x\nesp: 0x%x\neip: 00%x:0x%x\nss:  00%x\neflags:%i\n",	ctx.eax,ctx.ebx,ctx.ecx,ctx.edx,ctx.edi,ctx.esi,ctx.ebp,ctx.esp,ctx.cs,ctx.eip,ctx.ss);
	printf("Stack dump: \n");
	void* ret_addr = __builtin_frame_address(0);
	printf("#0 stack frame:0x%x\n",(uint32_t)ret_addr);
#endif
	halt();
	__builtin_unreachable();
}

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
#ifndef REGISTERS_H
#define REGISTERS_H
#include <stdint.h>
#ifdef AMD64

typedef struct registers
{
	uint64_t rax,rbx,rcx,rdx,rdi,rsi,rsp,rbp,rip,rflags;
	uint16_t cs, ss;
}__attribute__((packed))registers_t;
#else

typedef struct registers
{
   uint32_t eax,ebx,ecx,edx,edi,esi,esp,ebp,eip,eflags;
   uint16_t ss,cs;
} __attribute__((packed)) registers_t;

#endif // AMD64
#endif // REGISTERS_H
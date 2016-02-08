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
#include <stdint.h>
#include <kernel/compiler.h>
typedef struct {
    uint32_t eax, ebx, ecx, edx, esi, edi, esp, ebp, eip, eflags, cr3;
} registers_mt_t;
typedef struct task
{
	registers_mt_t regs;
	struct task* next;
	
}task_t;
void init_scheduler();
void create_task(task_t* task);
void preempt();
//ARCH_SPECIFIC void switch_task(registers_mt_t* old,registers_mt_t* new);
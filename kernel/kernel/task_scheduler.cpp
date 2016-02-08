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
#include <kernel/task_scheduler.h>
#include <kernel/registers.h>
#include <kernel/panic.h>
#include <kernel/timer.h>
#include <kernel/compiler.h>
#include <stdio.h>
#include <stdlib.h>
task_t* last_task = NULL;
ARCH_SPECIFIC uint32_t read_ip();
static task_t*running_task;
static task_t main_task;
static task_t other_task;
void createTask(task_t* task, void (*main)(), uint32_t flags, uint32_t* pagedir);
static void other_main()
{
    printf("Hello multitasking world!"); // Not implemented here...
    preempt();
}
 
void init_scheduler()
{
    // Get EFLAGS and CR3
    asm volatile("movl %%cr3, %%eax; movl %%eax, %0;":"=m"(main_task.regs.cr3)::"%eax");
    asm volatile("pushfl; movl (%%esp), %%eax; movl %%eax, %0; popfl;":"=m"(main_task.regs.eflags)::"%eax");
 
    createTask(&other_task, other_main, main_task.regs.eflags, (uint32_t*)main_task.regs.cr3);
    main_task.next = &other_task;
    other_task.next = &main_task;
 
    running_task = &main_task;
}
 
void createTask(task_t* task, void (*main)(), uint32_t flags, uint32_t* pagedir) 
{
    task->regs.eax = 0;
    task->regs.ebx = 0;
    task->regs.ecx = 0;
    task->regs.edx = 0;
    task->regs.esi = 0;
    task->regs.edi = 0;
    task->regs.eflags = flags;
    task->regs.eip = (uint32_t) main;
    task->regs.cr3 = (uint32_t) pagedir;
    task->regs.esp = (uint32_t) 0;
    task->next = NULL;
}
 
void preempt()
{
    task_t* last = running_task;
    running_task = running_task->next;
    //switch_task(&last->regs, &running_task->regs);
}
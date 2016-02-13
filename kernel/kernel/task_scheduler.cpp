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
#include <kernel/mm.h>
#include <string.h>
task_t* last_task = NULL;
extern "C" void jump_userspace();
extern "C" void switch_task(uint32_t,registers_mt_t* oldr, registers_mt_t* newr);
static task_t* running_task;
static task_t* main_task;
void CreateTask(task_t* task, void (*main)(), uint32_t flags, uint32_t* pagedir);
static void new_main()
{
	printf("Hello cool ass multitasking world\n");
	asm volatile("cli \t\n hlt");
}
static uint32_t placement = 0x90000000;
void init_scheduler()
{
	main_task = (task_t*)kmalloc(sizeof(task_t));
	memset(main_task,0,sizeof(task_t));
	// Get EFLAGS and CR3
	asm volatile("movl %%cr3, %%eax; movl %%eax, %0;":"=m"(main_task->regs.cr3)::"%eax");
	
	asm volatile("pushfl; movl (%%esp), %%eax; movl %%eax, %0; popfl;":"=m"(main_task->regs.eflags)::"%eax");
	
	kmmap(placement,1024);
	
	running_task = main_task;
	
	task_t* new_task = new task_t;
	
	CreateTask(new_task,new_main,main_task->regs.eflags,(uint32_t*)main_task->regs.cr3);
}
void CreateTask(task_t* task, void (*main)(), uint32_t flags, uint32_t* pagedir) 
{
	task->regs.eax = 0xDEADBEEF;
	task->regs.ebx = 0xDEADBEEF;
	task->regs.ecx = 0xDEADBEEF;
	task->regs.edx = 0xDEADBEEF;
	task->regs.esi = 0xDEADBEEF;
	task->regs.edi = 0xDEADBEEF;
	task->regs.eflags = flags;
	task->regs.eip = (uint32_t) main;
	task->regs.cr3 = (uint32_t) pagedir;
	task->regs.esp = (uint32_t) kmalloc(sizeof(4096));
	if(task->regs.esp == NULL)
		abort();//How did this even happen???
	task->next = NULL;
	placement += 4096 * 2;
	task_t* placement_task = running_task;
	if(running_task!=NULL){
		while(placement_task->next != nullptr){
			placement_task= placement_task->next;
		}
		placement_task->next = task;
	}
}
 
void preempt(uint32_t past_eip)
{	if(running_task->next != nullptr){
		task_t* last = running_task;
		running_task = running_task->next;
		printf("0x%X\n",&running_task->regs);
		printf("0x%X\n",&last->regs);
		switch_task(past_eip,&last->regs, &running_task->regs);
	}
	else
		return;
}
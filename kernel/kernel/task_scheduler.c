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
#include <stdlib.h>
task_t* last_task = NULL;
ARCH_SPECIFIC uint32_t read_ip();
uint32_t queued_tasks = 0;
void init_scheduler()
{
	// Allocate some memory for the first task
	task_t* main_task = kmalloc(sizeof(task_t));
	
	registers_t regs;
	// Get the main kernel thread's context
	get_thread_ctx(&regs);
	// Copy the registers that matter onto the main_task
	main_task->eax = regs.eax;
	main_task->ebx = regs.ebx;
	main_task->ecx = regs.ecx;
	main_task->edx = regs.edx;
	main_task->edi = regs.edi;
	main_task->esi = regs.esi;
	main_task->esp = regs.esp;
	main_task->ebp = regs.ebp;
	main_task->eip = read_ip(); // EIP will be updated each timer tick
	main_task->next = NULL; // There is no next task in early kernel, will be filled by the next task to be created

	last_task = main_task;
}
void create_task(task_t* task)
{
	task_t* tsk = last_task;
	for(int i = 0;i <= queued_tasks;i++){
		tsk = tsk->next;
	}
	tsk->next = task;
	queued_tasks++;
}
void delete_task(task_t* task)
{
	task_t* tsk = last_task;
	for(int i = 0;i <= queued_tasks;i++){
		if(tsk->next == task)
			tsk->next = task->next;
	}
	queued_tasks--;
}
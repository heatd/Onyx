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
 * File: scheduler.cpp
 *
 * Description: Contains the implementation of the kernel's thread scheduler
 *
 * Date: 4/3/2016
 *
 *
 **************************************************************************/
#include <kernel/scheduler.h>
#include <kernel/registers.h>
#include <kernel/panic.h>
#include <kernel/timer.h>
#include <kernel/compiler.h>
#include <stdio.h>
#include <stdlib.h>
#include <kernel/mm.h>
#include <string.h>
Task_t* last_thread = nullptr;
extern "C" void jump_userspace();
static Task_t* first_task;
Task_t* CurrentTask = nullptr;
void CreateTask(int id,void (*thread)());
/*	This is a version of _exit, but exits the thread instead of the process.
	It doesn't release memory, unmap or call destructors.
	It terminates the task from the scheduler, and yields the control
	It yields because it has no where to return to, as returning to the thread would cause disastrous consequences
	*/
void _exit_task()
{
	TerminateTask(CurrentTask);
	asm volatile("int $0x50"); // yield the current task
}
void CreateTask(Task_t* task,void (*thread)(), uint32_t cs, uint32_t ss)
{
	unsigned int* stack;

	task->regs.esp = (uint32_t)valloc(2) + 8192;
	if(!task->regs.esp)
		abort();
	stack = (unsigned int*)task->regs.esp;
	// Push the return address
	*--stack = (unsigned int)&_exit_task;
	//First, this stuff is pushed by the processor
	*--stack = 0x0202; //This is EFLAGS
	*--stack = cs;   //This is CS, our code segment
	*--stack = (unsigned int)thread; //This is EIP

	//Next, the stuff pushed by 'pusha'
	*--stack = 0; //EDI
	*--stack = 0; //ESI
	*--stack = 0; //EBP
	*--stack = 0; //Just an offset, no value
	*--stack = 0; //EBX
	*--stack = 0; //EDX
	*--stack = 0; //ECX
	*--stack = 0; //EAX

	//Now these are the data segments pushed by the IRQ handler
	*--stack = ss; //DS
	*--stack = ss; //ES
	*--stack = ss; //FS
	*--stack = ss; //GS
	task->regs.esp = (uint32_t)stack;
	task->next = nullptr;
	if(!first_task){
		first_task = task;
		task->next = first_task;
	}else{
		Task_t* new_task = first_task;
		task->next = first_task;
		while(new_task->next != first_task)
		{
			new_task = new_task->next;
		}
		new_task->next = task;
	}
}
void TerminateTask(Task_t* task)
{
	if(task != nullptr)
	{
		Task_t* search_task = first_task;
		while(search_task->next != task)
		{
			search_task = search_task->next;
		}
		search_task->next = task->next;
	}
}
extern "C" unsigned int SwitchTask(unsigned int OldEsp)
{
	if(CurrentTask != nullptr)
	{
		//Were we even running a task?
		CurrentTask->regs.esp = OldEsp; //Save the new esp for the thread
		CurrentTask = CurrentTask->next;
	} else
	{
		CurrentTask = first_task; //We just started multi-tasking, start with task 0
	}
	return CurrentTask->regs.esp; //Return new stack pointer to ASM
}

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
static Task_t* CurrentTask = nullptr;
void CreateTask(int id,void (*thread)());

void CreateTask(Task_t* task,void (*thread)()) 
{
	unsigned int* stack;
	
	task->regs.esp = (uint32_t)kmalloc(4096) + 4096;
	stack = (unsigned int*)task->regs.esp;
	//First, this stuff is pushed by the processor
	*--stack = 0x0202; //This is EFLAGS
	*--stack = 0x08;   //This is CS, our code segment
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
	*--stack = 0x10; //DS
	*--stack = 0x10; //ES
	*--stack = 0x10; //FS
	*--stack = 0x10; //GS
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
extern "C" unsigned int SwitchTask(unsigned int OldEsp){
	if(CurrentTask != nullptr){ //Were we even running a task?
		CurrentTask->regs.esp = OldEsp; //Save the new esp for the thread
		CurrentTask = CurrentTask->next;
	} else{
		CurrentTask = first_task; //We just started multi-tasking, start with task 0
	}
	return CurrentTask->regs.esp; //Return new stack pointer to ASM
}
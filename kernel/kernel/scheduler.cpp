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
Thread_t* last_thread = nullptr;
extern "C" void jump_userspace();
extern "C" void switch_task(unsigned int eip,registers_t* oldr, registers_t* newr);
static Thread_t threads[2];
int CurrentTask = -1;
void CreateTask(int id,void (*thread)());

void CreateTask(int id,void (*thread)()) 
{
	unsigned int* stack;
	
	threads[id].regs.esp = (uint32_t)kmalloc(4096) + 4096;
	stack = (unsigned int*)threads[id].regs.esp;
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
	threads[id].regs.esp = (uint32_t)stack;
}
extern "C" unsigned int SwitchTask(unsigned int OldEsp){
	if(CurrentTask != -1){ //Were we even running a task?
		threads[CurrentTask].regs.esp = OldEsp; //Save the new esp for the thread
  
	//Now switch what task we're on
	if(CurrentTask == 0)CurrentTask = 1;
		else CurrentTask = 0;	
	} else{
		CurrentTask = 0; //We just started multi-tasking, start with task 0
	}
 
	return threads[CurrentTask].regs.esp; //Return new stack pointer to ASM
}
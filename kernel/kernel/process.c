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
 * File: process.cpp
 *
 * Description: Contains the implementation of the PCB, and the data structures the kernel has to keep track of the processes
 *
 * Date: 18/3/2016
 *
 *
 **************************************************************************/
#include <kernel/process.h>
#include <kernel/spinlock.h>
#include <stdio.h>
#include <kernel/mm.h>

process_t* kernel = NULL;
process_t* last = NULL;
bool is_used[MAX_PID];
void process_init()
{
	memset(&is_used,0,sizeof(is_used));
	kernel = kmalloc(sizeof(process_t));
	memset(kernel,0,sizeof(process_t));
	kernel->data = 0xC0600000;
	kernel->brk  = 0xC0F00000;
	kernel->pid = generate_pid();
	kernel->threads[0] = get_current_thread();
	SetupFDT(kernel->fildes);
	last = kernel;
}
int process_add_thread(kthread_t* kt)
{
	for(int i = 0;i < MAX_THREADS; i++)
	{
		if(get_current_process()->threads[i] == NULL)
		{
			get_current_process()->threads[i] = kt;
			return 0;
		}
	}
	return 1;
}
int process_destroy_thread(kthread_t* kt)
{
	for(int i = 0;i < MAX_THREADS; i++)
	{
		if(get_current_process()->threads[i] == kt)
		{
			get_current_process()->threads[i] = NULL;
			return 0;
		}
	}
	return 1;
}
static spinlock_t spl;
void process_create(uint32_t data_seg,uint32_t brk)
{
	acquire(&spl);
	process_t* new_process = kmalloc(sizeof(process_t));
	last->next = new_process;
	new_process->data = data_seg;
	new_process->brk = brk;
	new_process->pid = generate_pid();
	last = new_process;
	SetupFDT(new_process->fildes);
	release(&spl);
}
void process_destroy(process_t* process)
{
	process_t* search = kernel;
	process_t* last_search = search;
	do {
		if(search == process)
		{
			last_search->next = search->next;
			kfree(search);
			return;
		}
		last_search = search;
		search = search->next;
	} while(search != process);
}
int generate_pid()
{
	//Search the array
	for(int i = 0;i < MAX_PID; i++)
	{
		if(is_used[i] == false)
		{
			is_used[i] = true;
			return i;
		}
	}
}
process_t* get_current_process()
{
	process_t* search = kernel;
	kthread_t* curr_thread = get_current_thread();
	if(!curr_thread)
		abort();
	// Search the linked list
	do {
		for(int i = 0;i < MAX_THREADS;i++)
		{
			if(search->threads[i] == curr_thread)
				return search;// If one of the threads match, return
		}
		search = search->next;
	} while(search->next != NULL);
		return NULL;
}
/*
  	UNIX system call: getpid(2)
  	Return value: returns the PID of the current process
*/
int sys_getpid()
{
	process_t* curr = get_current_process();
	return curr->pid;
}

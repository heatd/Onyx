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
namespace PCB
{
	process_t* kernel = nullptr;
	process_t* last = nullptr;
	bool is_used[MAX_PID];
	void Init()
	{
		memset(&is_used,0,sizeof(is_used));
		kernel = new process_t;
		memset(kernel,0,sizeof(process_t));
		kernel->data = 0xC0600000;
		kernel->brk  = 0xC0F00000;
		kernel->pid = GeneratePID();
		kernel->threads[0] = GetCurrentThread();
		SetupFDT(kernel->fildes);
		last = kernel;
	}
	int AddThread(KThread* kt)
	{
		for(int i = 0;i < MAX_THREADS; i++)
		{
			if(GetCurrentProcess()->threads[i] == nullptr)
			{
				GetCurrentProcess()->threads[i] = kt;
				return 0;
			}
		}
		return 1;
	}
	static spinlock_t spl;
	void CreatePCB(uint32_t data_seg,uint32_t brk)
	{
		acquire(&spl);
		process_t* new_process = new process_t;
		last->next = new_process;
		new_process->data = data_seg;
		new_process->brk = brk;
		new_process->pid = GeneratePID();
		last = new_process;
		SetupFDT(new_process->fildes);
		release(&spl);
	}
	void DestroyPCB(process_t* process)
	{
		process_t* search = kernel;
		process_t* last_search = search;
		do {
			if(search == process)
			{
				last_search->next = search->next;
				delete search;
				return;
			}
			last_search = search;
			search = search->next;
		} while(search != process);
	}
	int GeneratePID()
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
	process_t* GetCurrentProcess()
	{
		process_t* search = kernel;
		KThread* curr_thread = GetCurrentThread();
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
		} while(search->next != nullptr);
		return nullptr;
	}
}
/*
  	UNIX system call: getpid(2)
  	Return value: returns the PID of the current process
*/
int sys_getpid()
{
	process_t* curr = PCB::GetCurrentProcess();
	return curr->pid;
}

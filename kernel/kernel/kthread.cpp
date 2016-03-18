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
 * File: kthread.cpp
 *
 * Description: Contains KThread's implementation
 *
 * Date: 4/3/2016
 *
 *
 **************************************************************************/
#include <kernel/scheduler.h>
#include <kernel/kthread.h>
#include <string.h>
#include <stdio.h>
#include <kernel/watchdog.h>
extern Task_t* CurrentTask;
static uint32_t assignable_id = 0;
static KThread* first = nullptr;
static KThread* last = nullptr;
KThread* GetCurrentThread()
{
	KThread* kt = first;
	while(kt->next != nullptr)
	{
		if(kt->thread_task == CurrentTask)
		{
			return kt;
		}
		kt = kt->next;
	}
	return nullptr;
}
int ThreadMessage(unsigned int msg)
{
	switch(msg)
	{
		case KERN_ECHO:
			return MSG_KERN_ECHO_AND_ACK;
		default:
			return 0x7fffffff;
	}
}

KThread* CreateThread(KThread_Entry_point entry)
{
	KThread* kt = new KThread;

	if(!kt)
		return kt;

	kt->id = assignable_id;
	assignable_id++;
	kt->MessageCallback = ThreadMessage;
	kt->thread_entry = entry;

	kt->thread_task = new Task_t;
	if(first == nullptr)
	{
		first = kt;
	}
	else
		last->next = kt;
	last = kt;
	kt->next = nullptr;
	if(!kt->thread_task)
		return nullptr;

	memset(kt->thread_task,0,sizeof(Task_t));

	return kt;
}
void DestroyThread(KThread* kt)
{
	if(kt->IsThreadRunning() == true)
		kt->Terminate();
	kt->id = 0;

	kt->thread_entry = nullptr;

	delete kt->thread_task;
	delete kt;
}
bool KThread::IsThreadRunning()
{
	return is_running;
}
int KThread::GetID()
{
	return id;
}
KThread_Entry_point KThread::GetEntryPoint()
{
	return thread_entry;
}
void KThread::Start()
{
	is_running = true;
	CreateTask(thread_task,thread_entry,0x08,0x10);
}
void KThread::ThreadRuntime()
{
	thread_entry();
	Terminate();
}
void KThread::Terminate()
{
	is_running = false;
	TerminateTask(thread_task);
}

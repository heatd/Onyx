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
 * File: watchdog.cpp
 *
 * Description: Contains the implementation of the kernel's watchdog
 *
 * Date: 1/2/2016
 *
 *
 **************************************************************************/
#include <kernel/panic.h>
#include <kernel/watchdog.h>
#include <stdlib.h>
#include <kernel/timer.h>
#include <stdio.h>
namespace Spartix
{
	uint64_t last_tick;
	KThread* g_tobewatch;
	void WatchdogRoutine()
	{
	redo:
	if(Timer::GetTickCount() - 100 != last_tick)
		asm volatile("hlt");
	asm volatile("cli");
		int err_code = SendMessage(KERN_ECHO,g_tobewatch);
		if(err_code == MSG_KERN_THREAD_NOT_FOUND)
			panic("Fatal error: Watchdog response failed");
		else if(err_code == MSG_KERN_NO_RESPONSE)
			panic("Fatal error: Watchdog response failed");
		if(err_code != MSG_KERN_ECHO_AND_ACK)//The thread response was corrupted
			panic("Fatal error: Watchdog response corrupted");
		last_tick = Timer::GetTickCount();

	asm volatile("sti");
		goto redo;
	}
	Watchdog::Watchdog(KThread* kt)
	{
		if(!kt)
			return;
		to_be_watched = kt;
		watchdog = CreateThread(WatchdogRoutine);

		if(!watchdog)
			abort();
	}
	Watchdog::~Watchdog()
	{
		DestroyThread(watchdog);
		to_be_watched = nullptr;
		watchdog = nullptr;
	}
	void Watchdog::Start()
	{
		if(to_be_watched->IsThreadRunning() == false)
			return;
		watchdog->Start();
		g_tobewatch = this->to_be_watched;
	}
	void Watchdog::Stop()
	{
		watchdog->Terminate();
	}
}

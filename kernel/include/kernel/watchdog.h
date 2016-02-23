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
#pragma once
#include <kernel/kthread.h>
#include <kernel/message.h>
#define KERN_ECHO 0x1000
#define MSG_KERN_THREAD_NOT_FOUND 0x3000
#define MSG_KERN_NO_RESPONSE 0x200
#define MSG_KERN_ECHO_AND_ACK 0x2000
namespace Spartix
{
	class Watchdog
	{
	private:	
		KThread* watchdog;
		KThread* to_be_watched;
	public:
		Watchdog(KThread* kt);
		~Watchdog();
		void Stop();
		void Start();
	};
}

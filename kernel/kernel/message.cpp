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
 * File: message.cpp
 *
 * Description: Contains thread message passing routines (the implementation needs to be deepened)
 *
 * Date: 4/3/2016
 *
 *
 **************************************************************************/
#include <kernel/message.h>

namespace Spartix
{
	int SendMessage(unsigned int message,KThread* thread)
	{
		int ret;
		if(!thread)
			return MSG_KERN_NO_RESPONSE;
		if(thread->MessageCallback != nullptr)
			ret = thread->MessageCallback(message);

		return ret;
	}
}

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
 * File: sleep.c
 * 
 * Description: Implementation of ksleep
 * 
 * Date: 4/2/2016
 * 
 * 
 **************************************************************************/
#include <kernel/sleep.h>
void ksleep(long long ms)
{
	uint32_t ticks = GetTickCount();
	while(GetTickCount() - ticks != ms)
	{
		asm volatile("hlt");
	}
}

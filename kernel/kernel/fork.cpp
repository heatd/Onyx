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
#include <kernel/mm.h>
#include <string.h>
#include <unistd.h>
#include <kernel/kthread.h>
static pid_t current_pid = -1;
pid_t fork()
{
	current_pid++;
	VMM::pdirectory* newpd = VMM::CopyAddressSpace();
	switch_directory(newpd);
	KThread* kt = CreateThread((KThread_Entry_point)__builtin_return_address(0));
	kt->Start();
	return current_pid;
}

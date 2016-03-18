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
#include <kernel/process.h>
namespace PCB
{
	process_t* kernel = nullptr;
	void Init()
	{
		kernel = new process_t;
		memset(kernel,0,sizeof(process_t));
		kernel->data = 0xC0600000;
		kernel->brk  = 0xC0F00000;
		kernel->pid = -1;
		SetupFDT(kernel->fildes);
	}
}

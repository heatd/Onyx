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
#include <kernel/sbrk.h>
int brk(void *addr)
{
#ifdef is_spartix_kernel
	return __brk(addr);
#else
	__asm__ __volatile__ ("movl $3,%%eax\t\n movl %0,%%ebx"::"r" (addr));
	__asm__ __volatile__ ("int $0x80");
	int ret = 0;
	__asm__ __volatile__ ("mov %%eax,%0":"=a"(ret));
	return ret;
#endif
}

void *sbrk(uint32_t inc)
{
	return __sbrk(inc);
}

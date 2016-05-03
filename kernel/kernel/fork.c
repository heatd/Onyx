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
#include <stdio.h>
#include <kernel/process.h>
#include <kernel/panic.h>
int cnt = 0;
pid_t fork()
{
	pdirectory *newpd = vmm_fork();
	switch_directory(newpd,get_phys_addr(get_directory(),(uint32_t) newpd));
	kthread_t *kt = kthread_create(__builtin_return_address(0), cnt ? true : false,(uintptr_t) get_phys_addr(get_directory(),(uint32_t) newpd), (uintptr_t) newpd);
	if(!cnt)
		cnt++;
	process_t *p = process_create(0x600000,0x700000,NULL);
	kthread_start(kt);
	return p->pid;
}

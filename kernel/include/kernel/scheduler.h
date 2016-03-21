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
#include <stdint.h>
#include <kernel/compiler.h>
#include <kernel/registers.h>
#include <stdio.h>
typedef struct task
{
	_Bool is_kernel;
	registers_t regs;
	struct task* next;

}task_t;
void sched_create_task(task_t*,void (*thread)(),uint32_t,uint32_t);
void sched_terminate_task(task_t*);
unsigned int sched_switch_task(unsigned int old_esp);

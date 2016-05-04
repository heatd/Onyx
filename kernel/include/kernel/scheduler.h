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
#ifndef _SCHED_H
#define _SCHED_H
#include <stdint.h>
#include <stdbool.h>
#include <kernel/compiler.h>
#include <kernel/registers.h>
#include <kernel/vmm.h>
#include <stdio.h>
typedef struct task
{
	_Bool is_kernel;
	pdirectory *pgdir;
	pdirectory *vpgdir;
	uint32_t *stack;
	struct task *next;

}__attribute__((packed)) task_t;
void sched_create_task(task_t *task, void (*thread) (), uint32_t cs, uint32_t ss, _Bool is_fork);
void sched_terminate_task(task_t*);
unsigned int sched_switch_task(uint32_t *old_esp);
#endif

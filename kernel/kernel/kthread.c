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
 * File: kthread.c
 *
 * Description: Contains kthread's implementation
 *
 * Date: 4/3/2016
 *
 *
 **************************************************************************/
#include <kernel/scheduler.h>
#include <kernel/kthread.h>
#include <kernel/process.h>
#include <string.h>
#include <stdio.h>
#include <kernel/mm.h>
extern task_t *current_task;
static uint32_t assignable_id = 0;
static kthread_t *first = NULL;
static kthread_t *last = NULL;
#define KERNEL_DEFAULT_PGD 0x3f2000
kthread_t *get_current_thread()
{
	kthread_t *kt = first;
	do {
		if (kt->thread_task == current_task) {
			return kt;
		}
		kt = kt->next;
	} while (kt->next != NULL);
	return NULL;
}
extern _Bool is_initialized;
kthread_t *kthread_create(kthread_entry_point_t entry, _Bool is_user, uintptr_t cr3,uintptr_t vcr3,_Bool is_fork)
{
	kthread_t *kt = kmalloc(sizeof(kthread_t));

	if (!kt)
		return NULL;

	kt->id = assignable_id;
	assignable_id++;
	kt->thread_entry = entry;
	kt->is_user = is_user;
	kt->thread_task = kmalloc(sizeof(task_t));
	if(!kt->thread_task)
		return NULL;
	if(!cr3) {
		cr3 = KERNEL_DEFAULT_PGD;
		vcr3 = KERNEL_DEFAULT_PGD;
	}
	kt->thread_task->pgdir = (pdirectory *)cr3;
	kt->thread_task->vpgdir = (pdirectory *)vcr3;
	kt->is_fork = is_fork;
	if (first == NULL) {
		first = kt;
	} else
		last->next = kt;
	last = kt;
	kt->next = NULL;
	if (!kt->thread_task)
		return NULL;

	memset(kt->thread_task, 0, sizeof(task_t));

	return kt;
}

void kthread_destroy(kthread_t *kt)
{
	if (kthread_is_running(kt)) {
		kthread_terminate(kt);
	}
	kt->id = 0;

	kt->thread_entry = NULL;

	kfree(kt->thread_task);
	kfree(kt);
}

bool kthread_is_running(kthread_t *kt)
{
	return kt->is_running;
}

int kthread_get_id(kthread_t *kt)
{
	return kt->id;
}

kthread_entry_point_t kthread_get_entry_point(kthread_t *kt)
{
	return kt->thread_entry;
}

void kthread_start(kthread_t *kt)
{
	kt->is_running = true;
	sched_create_task(kt->thread_task, kt->thread_entry, kt->is_user ? 0x1b : 0x08, kt->is_user ? 0x23 : 0x10, kt->is_fork);
}

void kthread_terminate(kthread_t *kt)
{
	kt->is_running = false;
	sched_terminate_task(kt->thread_task);
}

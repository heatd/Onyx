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
#include <kernel/scheduler.h>
#include <stdbool.h>
typedef void (*kthread_entry_point_t)();
typedef struct kt
{
	// NEVER CHANGE THE FOLLOWING MEMBERS
	_Bool is_running;
	kthread_entry_point_t thread_entry;
	task_t* thread_task;
	struct kt* next;
	int id;

}kthread_t;
bool kthread_is_running(kthread_t*);
int kthread_get_id(kthread_t*);
kthread_entry_point_t kthread_get_entry_point(kthread_t*);
void kthread_start(kthread_t*);
void kthread_terminate(kthread_t*);
kthread_t* kthread_create(kthread_entry_point_t);
void 	kthread_destroy(kthread_t*);
kthread_t* get_current_thread();

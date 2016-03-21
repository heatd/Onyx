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
#include <kernel/fd.h>
#include <kernel/kthread.h>
#define MAX_THREADS 32
#define MAX_PID 6556
typedef struct process
{
	kthread_t* threads[MAX_THREADS];
	uint32_t data;
	uint32_t brk;
	int pid;
	fd_t fildes[MAX_FILDES];
	struct process* next;
}process_t;
void process_init();
void process_create(uint32_t data_seg,uint32_t brk);
int  generate_pid();
process_t* get_current_process();
void process_destroy(process_t* process);
int process_destroy_thread(kthread_t* kt);
int sys_getpid();

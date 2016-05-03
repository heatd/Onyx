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
 * File: exec.c
 *
 * Description: exec(2) implementation
 *
 * Date: 2/5/2016
 *
 *
 **************************************************************************/
#include <kernel/elf_loader.h>
#include <kernel/process.h>
#include <kernel/fs.h>
#include <kernel/kheap.h>
extern task_t *current_task;
/* Just a test version, doesn't take args except the program */
int exec(const char *path)
{
	process_t *process = process_create(0x700000,0x800000,NULL);
	fs_node_t *node = finddir_fs(fs_root, (char *) path);
	if(!node)
		return 1;
	char *buffer = kmalloc(4);
	/* Get the size of the file */
	size_t size = read_fs(node,0,0,buffer);
	kfree(buffer);
	/* Allocate a buffer large enough */
	buffer = kmalloc(size);
	memset(buffer, 0, size);
	/* Actually copy the data to the buffer */
	read_fs(node, 0, size, buffer);
	/* Load the Elf File*/
	kthread_t *kt = elf_load_file(buffer);
	/* Add the thread to the process */
	process_add_thread(process, kt);
	/* Start it */
	kthread_start(kt);
	/* Delete this process */

	return 0;
}

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
#include <fs/zero.h>
#include <kernel/fs.h>
uint32_t zero_read(fs_node_t *node, uint32_t offset, uint32_t size,
		  void *buffer)
{
	(void) node;
	(void) offset;
	memset(buffer,0,size);
	return size;
}
void zero_dev_init()
{
	/* Create a filesystem node for /dev/zero (the /dev/ should already be created)*/
	fs_node_t* zero = open_fs(NULL,0,0,"/dev/zero");
	if(!zero)
		abort();
	zero->flags = FS_CHARDEVICE;
	zero->read = &zero_read;
	zero->write = 0;
}

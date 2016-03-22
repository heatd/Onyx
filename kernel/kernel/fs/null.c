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
#include <fs/null.h>
#include <kernel/fs.h>
uint32_t null_write(fs_node_t*,uint32_t,uint32_t size,void* buffer)
{
	/* Writing to /dev/null is a no-op, no need to transfer data between the buffer and memory */
	return size;
}
void null_dev_init()
{
	/* Create a filesystem node for /dev/null (the /dev/ should already be created)*/
	fs_node_t* null = open_fs(NULL,0,0,"/dev/null");
	if(!null)
		abort();
	null->flags = FS_CHARDEVICE;
	null->read = 0;
	null->write = &null_write;
}

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
#include <kernel/fs.h>
#include <stdlib.h>
#include <kernel/tty.h>
#include <assert.h>
#include <kernel/vga.h>
fs_node_t *fs_root = 0;

uint32_t read_fs(fs_node_t * node, uint32_t offset, uint32_t size,
		 void *buffer)
{
	if (node->read != 0)
		return node->read(node, offset, size, buffer);
	else
		return 0;
}

uint32_t write_fs(fs_node_t * node, uint32_t offset, uint32_t size,
		  void *buffer)
{

	if (node->write != 0)
		return node->write(node, offset, size, buffer);
	else
		return 0;
}

fs_node_t *open_fs(fs_node_t * node, uint8_t read, uint8_t write,
		   const char *name)
{
	if (fs_root->open != 0)
		return fs_root->open(node, name);
}

void close_fs(fs_node_t * node)
{
	if (node->close != 0)
		return node->close(node);
}

struct dirent *readdir_fs(fs_node_t * node, uint32_t index)
{
	// Is the node a directory, and does it have a callback?
	if ((node->flags & 0x7) == FS_DIRECTORY || FS_ROOT &&
	    node->readdir != 0)
		return node->readdir(node, index);
	else
		return NULL;
}

fs_node_t *finddir_fs(fs_node_t * node, char *name)
{
	// Is the node a directory, and does it have a callback?
	if ((node->flags & 0x7) == FS_DIRECTORY || FS_ROOT &&
	    node->finddir != 0)
		return node->finddir(node, name);
	else
		return 0;
}

fs_node_t *mount_fs(const char *mountpoint, fs_node_t * dest)
{
	assert(mountpoint);
	assert(dest);

	fs_node_t *mount_node = finddir_fs(fs_root, (char *) mountpoint);
	if (!mount_node)
		return;

	mount_node->flags = FS_MOUNTPOINT;
	mount_node->ptr = dest;
	return mount_node;
}

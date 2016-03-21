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
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
struct fs_node;
struct dirent // One of these is returned by the readdir call, according to POSIX.
{
	char name[128]; // Filename.
	uint32_t ino;     // Inode number. Required by POSIX.
};
typedef uint32_t (*read_type_t)(struct fs_node*,uint32_t,uint32_t,void*);
typedef uint32_t (*write_type_t)(struct fs_node*,uint32_t,uint32_t,void*);
typedef struct fs_node* (*open_type_t)(struct fs_node*,const char* name);
typedef void (*close_type_t)(struct fs_node*);
typedef struct dirent * (*readdir_type_t)(struct fs_node*,uint32_t);
typedef struct fs_node * (*finddir_type_t)(struct fs_node*,char* name);

#define FS_FILE        	0x01
#define FS_DIRECTORY   	0x02
#define FS_CHARDEVICE  	0x03
#define FS_BLOCKDEVICE 	0x04
#define FS_PIPE        	0x05
#define FS_SYMLINK     	0x06
#define FS_MOUNTPOINT  	0x08 // Is the file an active mountpoint?
#define FS_ROOT		0x09
typedef struct fs_node
{
   char name[128];     		// The filename.
   uint32_t mask;        // The permissions mask.
   uint32_t uid;         // The owning user.
   uint32_t gid;         // The owning group.
   uint32_t flags;       // Includes the node type. See #defines above.
   uint32_t inode;       // This is device-specific - provides a way for a filesystem to identify files.
   uint32_t length;      // Size of the file, in bytes.
   uint32_t impl;        // An implementation-defined number.
   read_type_t read;
   write_type_t write;
   open_type_t open;
   close_type_t close;
   readdir_type_t readdir;
   finddir_type_t finddir;
   struct fs_node* ptr; // Used by mountpoints and symlinks.
   struct fs_node* next;
} fs_node_t;

extern fs_node_t *fs_root; // The root of the filesystem.

// Standard read/write/open/close functions. Note that these are all suffixed with
// _fs to distinguish them from the read/write/open/close which deal with file descriptors
// not file nodes.
uint32_t read_fs(fs_node_t *node, uint32_t offset, uint32_t size, void* buffer);
uint32_t write_fs(fs_node_t *node, uint32_t offset, uint32_t size, void* buffer);
fs_node_t* open_fs(fs_node_t *node, uint8_t read, uint8_t write,const char* name);
void close_fs(fs_node_t *node);
fs_node_t* mount_fs(const char* mountpoint, fs_node_t* dest);
struct dirent *readdir_fs(fs_node_t *node, uint32_t index);
fs_node_t *finddir_fs(fs_node_t *node, char* name);

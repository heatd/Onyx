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
#include <kernel/fs.h>
#include <stdint.h>
typedef struct tar_header
{
    	char filename[100];
    	char mode[8];
    	char uid[8];
    	char gid[8];
    	char size[12];
    	char mtime[12];
    	char chksum[8];
    	char typeflag;
}tar_header_t;

#define TAR_TYPE_FILE		'\0'
#define TAR_TYPE_HARD_LNK 	'1'
#define TAR_TYPE_SYMLNK		'2'
#define TAR_TYPE_CHAR_SPECIAL	'3'
#define TAR_TYPE_BLOCK_SPECIAL	'4'
#define TAR_TYPE_DIR		'5'
//I will only need to support these types,so more isn't needed
uint32_t tar_get_size(const char *in);
unsigned int tar_parse(uint32_t address);
fs_node_t* initrd_init(uint32_t addr);

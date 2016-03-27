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
#ifndef _MMAN_H
#define _MMAN_H

#define PROT_NONE	0x0
#define PROT_READ	0x1
#define PROT_WRITE	0x2
#define PROT_EXEC 	0x4

#define MAP_SHARED	0x0
#define MAP_PRIVATE	0x2
#define MAP_ANONYMOUS	0x4
#define MAP_ANON	MAP_ANONYMOUS
#define MAP_DENYWRITE	0x6
#define MAP_EXECUTABLE	0x8
#define MAP_FILE	0xB
#define MAP_FIXED	0xD
#define MAP_GROWSDOWN	0xF
#define MAP_LOCKED	0x10
#define MAP_NONBLOCK	0x12
#define MAP_NORESERVE	0x14
#define MAP_STACK	0x16
#define MAP_UNINITIALIZED 0x18

void* mmap(void* addr, size_t len,int prot,int flags,int fildes,off_t off);
int munmap(void* addr,size_t len);



#endif

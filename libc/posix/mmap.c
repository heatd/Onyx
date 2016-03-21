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
#include <sys/syscall.h>
#if defined(__is_spartix_kernel)
#include <kernel/vmm.h>
#endif				// __is_spartix_kernel
#include <sys/mman.h>
#include <stdint.h>
// fildes and offset are ignored
// void* mmap(void* addr, size_t len,int prot,int flags,int fildes,off_t off)
// {
//      if(flags == MAP_FIXED && ((uintptr_t)addr % 4096) == 1)
//              return NULL;
//      if((len % 4096) == 1)
//              return NULL;
// #if defined(__is_spartix_kernel)
//      kmmap(addr,len / 4096,prot,flags,0,0);
// #else
//      SYSCALL(MMAP_SYSCALL,(uint32_t)addr,len,flags,fildes,off);
// #endif // __is_spartix_kernel
// }
// int munmap(void* addr,size_t len)
// {
// #if defined(__is_spartix_kernel)
//      kmunmap(addr,len);
// #else
//      
// #endif // __is_spartix_kernel
// }

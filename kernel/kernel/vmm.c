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
#include <kernel/vmm.h>
#include <string.h>
#include <stdio.h>
#include <kernel/panic.h>
void* kmmap(uint32_t virt, uint32_t npages,uint32_t flags)
{
	return _kmmap(virt, npages, flags);
}
void *valloc(size_t npages,_Bool is_kernel)
{
	if (!npages)
		return NULL;
	void *vaddr = vmm_alloc_addr(npages, is_kernel);
	uint32_t flags = 0;
	if(unlikely(is_kernel == true)) {
		flags = MAP_WRITE | MAP_USER;
	}else {
		flags = MAP_WRITE | MAP_USER;
	}
	void *mem = kmmap((uint32_t) vaddr, npages,flags);
	if (!mem)
		return NULL;
	printf("mem: %p\n",mem);
	if(mem != vaddr) {
		panic("Something is wrong!");
	}
	return mem;
}
void vfree(void *ptr, uint32_t npages)
{
	if (!npages)
		return;
	if (!ptr)
		return;
	kmunmap(ptr, npages);
	vmm_free_addr(ptr);
}
int switch_directory (pdirectory* dir)
{
	return _switch_directory(dir);
}
void kmunmap(void *virt, size_t npages)
{
	_kmunmap(virt,npages);
}
pdirectory* vmm_fork()
{
	return _vmm_fork();
}

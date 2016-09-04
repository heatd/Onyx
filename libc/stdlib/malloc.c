#include <kernel/heap.h>
void *malloc(size_t size)
{
	return heap_malloc(size);
}
void free(void *ptr)
{
	return heap_free(ptr);
}
void *calloc(size_t nmemb, size_t size)
{
	void *mem = malloc(size * nmemb);
	if(!mem)
		return NULL;
	memset(mem, 0, size * nmemb);
	return mem;
}
void *realloc(void *ptr, size_t newsize)
{
	void *newbuf = malloc(newsize);
	block_t *block = (block_t*)((char*)(ptr) - sizeof(block_t));
	size_t block_size = block->size;
	memcpy(newbuf, ptr , block_size);
	free(ptr);
	return newbuf;
}
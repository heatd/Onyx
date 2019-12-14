mm-y:= bootmem.o kasan.o page.o pagealloc.o slab.o vm_object.o vm.o malloc/aligned_alloc.o malloc/calloc.o \
	malloc/expand_heap.o malloc/malloc_usable_size.o malloc/malloc.o malloc/memalign.o \
	malloc/posix_memalign.o

obj-y+= $(patsubst %, kernel/mm/%, $(mm-y))

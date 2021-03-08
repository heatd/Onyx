mm-y:= bootmem.o page.o pagealloc.o vm_object.o vm.o malloc/aligned_alloc.o malloc/calloc.o \
	malloc/expand_heap.o malloc/malloc_usable_size.o malloc/malloc.o malloc/memalign.o \
	malloc/posix_memalign.o flush.o vm_active.o

mm-$(CONFIG_KASAN)+= kasan.o

obj-y+= $(patsubst %, kernel/mm/%, $(mm-y))

mm-y:= bootmem.o page.o pagealloc.o vm_object.o vm.o flush.o slab.o vmalloc.o

malloc-y:=  malloc/aligned_alloc.o malloc/calloc.o \
			malloc/expand_heap.o malloc/malloc_usable_size.o malloc/malloc.o malloc/memalign.o \
			malloc/posix_memalign.o malloc/onyx.o

ifneq ($(ONYX_DONT_USE_TREE_MALLOC), true)
mm-y:= $(mm-y) $(malloc-y)
endif

mm-$(CONFIG_KASAN)+= asan/asan.o

obj-y+= $(patsubst %, kernel/mm/%, $(mm-y))

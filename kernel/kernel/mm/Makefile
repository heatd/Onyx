mm-y:= bootmem.o page.o pagealloc.o vm_object.o vm.o vmalloc.o reclaim.o anon.o mincore.o page_lru.o swap.o rmap.o slab_cache_pool.o madvise.o
mm-$(CONFIG_KUNIT)+= vm_tests.o
mm-$(CONFIG_X86)+= memory.o
mm-$(CONFIG_RISCV)+= memory.o

ifeq ($(CONFIG_KASAN), y)
obj-y_NOKASAN+= kernel/mm/asan/asan.o kernel/mm/asan/quarantine.o
endif

mm-$(CONFIG_PAGE_OWNER)+= page_owner.o

obj-y_NOKASAN+= kernel/mm/slab.o

obj-y+= $(patsubst %, kernel/mm/%, $(mm-y))

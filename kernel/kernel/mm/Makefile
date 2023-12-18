mm-y:= bootmem.o page.o pagealloc.o vm_object.o vm.o vmalloc.o reclaim.o amap.o anon.o
mm-$(CONFIG_KUNIT)+= vm_tests.o

ifeq ($(CONFIG_KASAN), y)
obj-y_NOKASAN+= kernel/mm/asan/asan.o kernel/mm/asan/quarantine.o
endif

obj-y_NOKASAN+= kernel/mm/slab.o

obj-y+= $(patsubst %, kernel/mm/%, $(mm-y))

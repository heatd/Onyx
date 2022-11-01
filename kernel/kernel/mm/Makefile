mm-y:= bootmem.o page.o pagealloc.o vm_object.o vm.o flush.o vmalloc.o

ifeq ($(CONFIG_KASAN), y)
obj-y_NOKASAN+= kernel/mm/asan/asan.o kernel/mm/asan/quarantine.o
endif

obj-y_NOKASAN+= kernel/mm/slab.o

obj-y+= $(patsubst %, kernel/mm/%, $(mm-y))

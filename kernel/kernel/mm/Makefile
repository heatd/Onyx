mm-y:= bootmem.o page.o pagealloc.o vm_object.o vm.o flush.o slab.o vmalloc.o

mm-$(CONFIG_KASAN)+= asan/asan.o

obj-y+= $(patsubst %, kernel/mm/%, $(mm-y))

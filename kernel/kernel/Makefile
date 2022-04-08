kern-y+= acpi.o acpi_osl.o arc4random.o binfmt.o copy.o cppnew.o cpprt.o crc32.o dev.o dma.o dpc.o \
	driver.o exceptions.o font.o framebuffer.o futex.o i2c.o id_manager.o init.o initrd.o \
	irq.o kernelinfo.o kernlog.o ktest.o modules.o object.o panic.o percpu.o \
	power_management.o proc_event.o process.o pid.o ptrace.o random.o ref.o signal.o \
	smp.o spinlock.o symbol.o time.o timer.o utils.o wait_queue.o \
	worker.o cred.o list.o softirq.o cputime.o rlimit.o handle.o ctor.o internal_abi.o ssp.o \
	cmdline.o syscall_thunk.o vdso.o sysinfo.o

kern-$(CONFIG_UBSAN)+= ubsan.o

kern-y+= fonts/font.o photon/photon.o binfmt/elf.o binfmt/elf64.o binfmt/exec.o \
	libdict/rb_tree.o libdict/tree_common.o libdict/wb_tree.o time/tickless.o binfmt/shebang.o

kern-$(CONFIG_KTRACE)+= ktrace.o

obj-y+= $(patsubst %, kernel/%, $(kern-y)) 

include kernel/mm/Makefile
include kernel/net/Makefile
include kernel/fs/Makefile
include kernel/input/Makefile
include kernel/tty/Makefile
include kernel/sched/Makefile

kernel/syscall_thunk.cpp: generate_syscall_bits.py $(ARCHDIR)/syscall_table.json
	mkdir -p include/onyx/gen
	python3 generate_syscall_bits.py $(ARCHDIR)/syscall_table.json kernel/syscall_thunk.cpp include/onyx/gen/syscall.h

include/onyx/gen/syscall.h: kernel/syscall_thunk.cpp

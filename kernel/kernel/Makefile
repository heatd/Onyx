kern-y+= arc4random.o binfmt.o compression.o copy.o cppnew.o cpprt.o crc32.o dev.o dma.o dpc.o \
	driver.o exceptions.o font.o framebuffer.o futex.o i2c.o id_manager.o init.o initrd.o \
	irq.o uname.o kernlog.o ktest.o modules.o object.o panic.o percpu.o \
	power_management.o proc_event.o process.o pid.o ptrace.o random.o ref.o signal.o \
	smp.o spinlock.o symbol.o tasklet.o time.o timer.o utils.o wait_queue.o \
	worker.o cred.o list.o softirq.o cputime.o rlimit.o handle.o ctor.o internal_abi.o ssp.o \
	cmdline.o syscall_thunk.o vdso.o sysinfo.o memstream.o perf.o radix.o rcupdate.o iovec_iter.o \
	maple_tree.o bug.o lru.o cpio.o fork.o exit.o

kern-$(CONFIG_UBSAN)+= ubsan.o

kern-y+= photon/photon.o binfmt/elf.o binfmt/module_loader.o binfmt/exec.o \
	libdict/rb_tree.o libdict/tree_common.o libdict/wb_tree.o time/tickless.o binfmt/shebang.o
kern-$(CONFIG_COMPAT)+= binfmt/elf_compat.o

kern-$(CONFIG_KTRACE)+= ktrace.o

kern-$(CONFIG_KUNIT)+= kunit.o

kern-$(CONFIG_KCOV)+= kcov.o
kern-$(ARCH_HAS_JUMP_LABELS)+= jump_label.o
kern-$(CONFIG_KUNIT)+= printf_tests.o test_maple_tree.o

kern-y+= irq.trace.o refcount.trace.o rcupdate.trace.o vm.trace.o sched.trace.o

obj-y+= $(patsubst %, kernel/%, $(kern-y)) 

include kernel/mm/Makefile
include kernel/net/Makefile
include kernel/fs/Makefile
include kernel/input/Makefile
include kernel/tty/Makefile
include kernel/sched/Makefile
include kernel/kcsan/Makefile
include kernel/fonts/Makefile
include kernel/block/Makefile

kernel/syscall_thunk.cpp: generate_syscall_bits.py $(ARCHDIR)/syscall_table.json
	mkdir -p include/onyx/gen
	python3 generate_syscall_bits.py $(ARCHDIR)/syscall_table.json kernel/syscall_thunk.cpp include/onyx/gen/syscall.h

include/onyx/gen/trace_%.h: trace/trace_%.json trace/gentrace.py
	python3 trace/gentrace.py $< include/onyx/gen/trace_$*.h kernel/$*.trace.cpp

kernel/%.trace.cpp: trace/trace_%.json trace/gentrace.py
	python3 trace/gentrace.py $< include/onyx/gen/trace_$*.h kernel/$*.trace.cpp

kernel/irq.o: include/onyx/gen/trace_irq.h

include/onyx/include/refcount.h: include/onyx/gen/trace_refcount.h

kernel/rcupdate.o: include/onyx/gen/trace_rcupdate.h

include/onyx/gen/syscall.h: kernel/syscall_thunk.cpp

kernel/kcov.o: CFLAGS+=-fno-sanitize-coverage=trace-pc

kernel/mm/vm.o kernel/process.o: include/onyx/gen/trace_vm.h

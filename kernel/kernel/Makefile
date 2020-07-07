kern-y+= acpi.o acpi_osl.o arc4random.o binfmt.o copy.o cppnew.o cpprt.o crc32.o dev.o dma.o dpc.o \
	driver.o exceptions.o font.o framebuffer.o futex.o i2c.o id_manager.o init.o initrd.o \
	irq.o kernelinfo.o kernlog.o ktest.o modules.o object.o panic.o percpu.o \
	power_management.o proc_event.o process.o ptrace.o random.o ref.o scheduler.o signal.o \
	smp.o spinlock.o symbol.o time.o timer.o tty.o utils.o video.o vterm.o wait_queue.o \
	worker.o cred.o list.o softirq.o mutex.o cputime.o

kern-$(CONFIG_UBSAN)+= ubsan.o

kern-y+= fonts/font.o photon/photon.o binfmt/elf.o binfmt/elf64.o binfmt/exec.o \
	libdict/rb_tree.o libdict/tree_common.o libdict/wb_tree.o time/tickless.o binfmt/shebang.o

kern-$(CONFIG_KTRACE)+= ktrace.o

obj-y+= $(patsubst %, kernel/%, $(kern-y)) 

include kernel/mm/Makefile
include kernel/net/Makefile
include kernel/fs/Makefile
include kernel/input/Makefile

x86_64-y:= acpi/acpi.o apic.o atomic.o avx.o boot.o copy_user.o copy.o cpu.o debug.o \
	desc_load.o disassembler.o entry.o exit.o fpu.o gdt.o idt.o interrupts.o irq.o \
	isr.o kvm.o mce.o multiboot2.o paging.o pat.o pic.o pit.o ptrace.o serial.o signal.o smbios.o \
	smp_trampoline.o smp.o spinlock.o strace.o syscall_table.o syscall.o thread.o tsc.o \
	tss.o vdso_helper.o vdso.o vm.o process.o powerctl.o

x86_64-$(CONFIG_KTRACE)+= ktrace.o fentry.o

obj-y+= $(patsubst %, arch/x86_64/%, $(x86_64-y))

arch/x86_64/vdso_helper.o: arch/x86_64/vdso_helper.S onyx-vdso.so.0 kernel.config
		@$(CC) -c $(CPPFLAGS) -o $@ $<

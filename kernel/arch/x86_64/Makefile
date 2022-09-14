x86_64-y:= apic.o avx.o boot.o copy_user.o copy.o cpu.o debug.o \
	desc_load.o disassembler.o entry.o exit.o fpu.o gdt.o idt.o interrupts.o irq.o \
	isr.o kvm.o mce.o multiboot2.o mmu.o pat.o pic.o pit.o ptrace.o signal.o smbios.o \
	smp_trampoline.o smp.o strace.o syscall.o thread.o tsc.o \
	tss.o vdso_helper.o vm.o process.o powerctl.o alternatives.o random.o \
	hpet.o

x86_64-$(CONFIG_KTRACE)+= ktrace.o fentry.o
x86_64-$(CONFIG_ACPI)+= acpi/acpi.o

obj-y+= $(patsubst %, arch/x86_64/%, $(x86_64-y))

arch/x86_64/vdso_helper.o: arch/x86_64/vdso_helper.S onyx-vdso.so.0 kernel.config
		@$(CC) -c $(CPPFLAGS) -o $@ $<

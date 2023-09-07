x86_64-y:= apic.o avx.o boot.o copy_user.o copy.o cpu.o debug.o \
	desc_load.o disassembler.o entry.o exit.o fpu.o gdt.o idt.o interrupts.o irq.o \
	isr.o kvm.o mce.o multiboot2.o mmu.o pat.o pic.o pit.o ptrace.o signal.o smbios.o \
	realmode.o smp.o strace.o syscall.o thread.o tsc.o \
	tss.o vdso_helper.o vm.o process.o powerctl.o alternatives.o random.o \
	hpet.o code_patch.o

x86_64-$(CONFIG_KTRACE)+= ktrace.o fentry.o
x86_64-$(CONFIG_ACPI)+= acpi/acpi.o

x86_64-$(CONFIG_X86_RETHUNK)+= rethunk.o

x86_64-$(CONFIG_EFI)+= efi.o

obj-$(CONFIG_EFI)_NOKASAN+= arch/x86_64/efistub/early.o

obj-y+= $(patsubst %, arch/x86_64/%, $(x86_64-y))

arch/x86_64/vdso_helper.o: arch/x86_64/vdso_helper.S onyx-vdso.so.0 kernel.config
	@$(CC) -c $(CPPFLAGS) -o $@ $<

arch/x86_64/efistub/early.o: CFLAGS:=$(filter-out -flto -mindirect-branch=thunk -mfunction-return=thunk-extern -mcmodel=kernel -fsanitize=undefined, $(CFLAGS)) -fPIE -fno-stack-protector

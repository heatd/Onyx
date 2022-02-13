riscv-y:= image.o fpu.o copy_user.o stubs.o vdso_helper.o early_paging.o entry.o virt-uart.o mmu.o interrupts.o traps.o usercopy.o

obj-y+= $(patsubst %, arch/riscv64/%, $(riscv-y))

arch/riscv64/vdso_helper.o: arch/riscv64/vdso_helper.S onyx-vdso.so.0 kernel.config
		$(CC) -c $(CFLAGS) $(CPPFLAGS) -mno-relax -o $@ $<

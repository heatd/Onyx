arm64-y:= image.o fpu.o copy_user.o stubs.o vdso_helper.o mmu.o early_mmu.o virt-uart.o entry.o traps.o interrupts.o

obj-y+= $(patsubst %, arch/arm64/%, $(arm64-y))

arch/arm64/vdso_helper.o: arch/arm64/vdso_helper.S onyx-vdso.so.0 .config
		$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

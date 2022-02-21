arm64-y:= image.o fpu.o copy_user.o stubs.o vdso_helper.o mmu.o

obj-y+= $(patsubst %, arch/arm64/%, $(arm64-y))

arch/arm64/vdso_helper.o: arch/arm64/vdso_helper.S onyx-vdso.so.0 kernel.config
		$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

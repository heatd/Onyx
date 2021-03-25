riscv-y:= image.o fpu.o

obj-y+= $(patsubst %, arch/riscv64/%, $(riscv-y))

arch/riscv64/vdso_helper.o: arch/riscv/vdso_helper.S onyx-vdso.so.0 kernel.config
		@$(CC) -c $(CPPFLAGS) -o $@ $<

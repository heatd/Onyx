generic-builtins-y:=absvdi2.o \
  	absvsi2.o \
  	absvti2.o \
  	addvdi3.o \
  	addvsi3.o \
  	addvti3.o \
  	ashldi3.o \
  	ashlti3.o \
  	ashrdi3.o \
  	ashrti3.o \
  	bswapdi2.o \
  	bswapsi2.o \
  	clzdi2.o \
  	clzsi2.o \
  	clzti2.o \
  	cmpdi2.o \
  	cmpti2.o \
  	ctzdi2.o \
  	ctzsi2.o \
  	ctzti2.o \
  	divdi3.o \
  	divmoddi4.o \
  	divmodsi4.o \
  	divmodti4.o \
  	divsi3.o \
  	divti3.o \
	ffsdi2.o \
  	ffssi2.o \
  	ffsti2.o \
  	int_util.o \
  	lshrdi3.o \
  	lshrti3.o \
  	moddi3.o \
  	modsi3.o \
  	modti3.o \
  	mulodi4.o \
  	mulosi4.o \
  	muloti4.o \
  	multi3.o \
  	mulvdi3.o \
  	mulvsi3.o \
  	mulvti3.o \
  	negdi2.o \
  	negti2.o \
  	negvdi2.o \
  	negvsi2.o \
  	negvti2.o \
  	paritydi2.o \
  	paritysi2.o \
  	parityti2.o \
  	popcountdi2.o \
  	popcountsi2.o \
  	popcountti2.o \
  	subvdi3.o \
  	subvsi3.o \
  	subvti3.o \
  	trampoline_setup.o \
  	ucmpdi2.o \
  	ucmpti2.o \
  	udivdi3.o \
  	udivmoddi4.o \
  	udivmodsi4.o \
  	udivmodti4.o \
  	udivsi3.o \
  	udivti3.o \
  	umoddi3.o \
  	umodsi3.o \
  	umodti3.o \
	#atomic_flag_clear.o \
    #atomic_flag_clear_explicit.o \
    #atomic_flag_test_and_set.o \
    #atomic_flag_test_and_set_explicit.o \
    #atomic_signal_fence.o \
    #atomic_thread_fence.o

soft-float-y: \
  	fixdfdi.o \
  	fixdfsi.o \
  	fixdfti.o \
  	fixsfdi.o \
  	fixsfsi.o \
  	fixsfti.o \
  	fixunsdfdi.o \
  	fixunsdfsi.o \
  	fixunsdfti.o \
  	fixunssfdi.o \
  	fixunssfsi.o \
  	fixunssfti.o \
  	floatdidf.o \
  	floatdisf.o \
  	floatsidf.o \
  	floatsisf.o \
  	floattidf.o \
  	floattisf.o \
  	floatundidf.o \
  	floatundisf.o \
  	floatunsidf.o \
  	floatunsisf.o \
  	floatuntidf.o \
  	floatuntisf.o \
  	fp_mode.o \
	powidf2.o \
  	powisf2.o \
	mulsc3.o \
	divdc3.o \
	divsc3.o \
	muldc3.o \
	adddf3.o \
  	addsf3.o \
	divdf3.o \
	divsf3.o \
	muldf3.o \
	mulsf3.o \
	subdf3.o \
  	subsf3.o \
	comparedf2.o \
  	comparesf2.o

x86_64_builtins-y:=cpu_model.o \
	muldi3.o

riscv64_builtins-y:=riscv/muldi3.o \
	riscv/save.o \
	riscv/restore.o \
	atomic.o

arm64_builtins-y:=aarch64/fp_mode.o

builtins-y:= $(generic-builtins-y) $($(ONYX_ARCH)_builtins-y)

obj-y+= $(patsubst %, lib/compiler-rt/builtins/%, $(builtins-y))

lib/compiler-rt/builtins/%.o: CFLAGS+=-fno-builtin -fno-lto
